# services

The logic that sits between the API or pipeline and where data is kept. Routes
and workers call into these; the services handle the in-memory store and the
database.

## Files

- **state.py** — the live, in-memory store of recent events. Keeps the newest few
  hundred and is safe to use from several threads at once.
- **events_archive.py** — saves finished events to the database and reads back the
  history, with filtering and paging.
- **notifications.py** — when a finished event is serious enough for a tenant, it
  works out who to alert. Delivery is stubbed for now and only logs the intent.
- **tenants.py** — the tenant registry: seeds tenants on first run, registers them
  with Wazuh, keeps a fast cache of each tenant's alert threshold, and handles
  reads and edits for the API.
- **users.py** — user accounts: the first admin, logging in, and admin actions to
  create or deactivate users.
