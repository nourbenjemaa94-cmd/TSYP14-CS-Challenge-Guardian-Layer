# Scenarios

One-command jury runs.

- `onboarding.ps1` / `onboarding.sh` — start Guardian with heuristic-only
  onboarding and send `twin-alt` 21 times. Writes
  `guardian/logs/onboarding-<UTC>.log`.
- Other attack modes: from `guardian/`, `python -m mocks.mock_twin --mode <name>`.
