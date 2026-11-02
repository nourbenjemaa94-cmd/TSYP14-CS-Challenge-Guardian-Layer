"""Start Guardian with one worker.

Keys are read from the environment or from `.env` in this directory.
Partner addresses come from `config.example.yaml` or from `GUARDIAN_CONFIG`.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
os.environ["PYTHONPATH"] = str(SRC) + os.pathsep + os.environ.get("PYTHONPATH", "")
sys.path.insert(0, str(SRC))


def main() -> None:
    import uvicorn

    from guardian.config import default_config_path, load_config

    config = load_config(default_config_path())
    uvicorn.run(
        "guardian.main:app",
        host=config.http_host,
        port=config.http_port,
        workers=1,
    )


if __name__ == "__main__":
    main()
