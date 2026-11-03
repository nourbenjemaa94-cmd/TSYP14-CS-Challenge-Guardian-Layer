#!/usr/bin/env bash
# Pull the Guardian chat and embedding models from a local Ollama server.
# Reads guardian/.env, then guardian/.env.example. Does not change either file.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/guardian/.env"
EXAMPLE_FILE="$ROOT/guardian/.env.example"
TAGS_URL="http://127.0.0.1:11434/api/tags"

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

dotenv_value() {
    file="$1"
    name="$2"
    if [ ! -f "$file" ]; then
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*) continue ;;
        esac
        key="${line%%=*}"
        value="${line#*=}"
        key="$(printf '%s' "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        if [ "$key" != "$name" ]; then
            continue
        fi
        value="$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        case "$value" in
            \"*\") value="${value#\"}"; value="${value%\"}" ;;
            \'*\') value="${value#\'}"; value="${value%\'}" ;;
        esac
        printf '%s' "$value"
        return 0
    done < "$file"
}

model_name() {
    name="$1"
    value="$(dotenv_value "$ENV_FILE" "$name" || true)"
    if [ -n "$value" ]; then
        printf '%s' "$value"
        return 0
    fi
    dotenv_value "$EXAMPLE_FILE" "$name" || true
}

if ! ollama --version; then
    fail "Ollama is not installed or not on PATH. Install Ollama, then run this script again."
fi

chat_model="$(model_name GUARDIAN_LLM_MODEL)"
embed_model="$(model_name GUARDIAN_EMBED_MODEL)"
if [ -z "$chat_model" ]; then
    fail "GUARDIAN_LLM_MODEL is empty in guardian/.env and guardian/.env.example."
fi
if [ -z "$embed_model" ]; then
    fail "GUARDIAN_EMBED_MODEL is empty in guardian/.env and guardian/.env.example."
fi

if ! curl -fsS --max-time 5 "$TAGS_URL" >/dev/null; then
    fail "Ollama is not reachable at http://127.0.0.1:11434. Start Ollama, then run this script again."
fi

ollama pull "$chat_model"
if [ "$embed_model" != "$chat_model" ]; then
    ollama pull "$embed_model"
fi

curl -fsS --max-time 10 "$TAGS_URL" | python -c 'import json,sys; data=json.load(sys.stdin); [print(model.get("name","")) for model in data.get("models") or [] if model.get("name")]'
