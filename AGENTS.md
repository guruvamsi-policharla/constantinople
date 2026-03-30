# Constantinople

## Common Commands

Use the `justfile` for all testing, linting, and formatting operations:

- `just test` — Run all tests (includes doc tests)
- `just lint` — Full lint: format check + doc check + clippy (denies warnings)
- `just fmt-fix` — Auto-fix formatting
- `just fmt-check` — Check formatting without fixing
- `just build` — Build the entire workspace

Aliases: `just t` (test), `just l` (lint), `just f` (fmt-fix).
