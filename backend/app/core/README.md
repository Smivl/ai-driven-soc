# core

App-wide settings and security helpers used across the backend.

## Files

- **config.py** — all settings in one place, with safe dev defaults that can be
  overridden in a .env file, so nothing secret is hard-coded for real use.
- **security.py** — hashing and checking passwords, and creating and reading the
  signed login tokens.
