# models

The database tables and the connection setup. The database is the lasting record
of tenants, users, and finished events.

## Files

- **db.py** — sets up the database connection and sessions, creates the tables on
  startup, and applies small column additions safely.
- **event.py** — the archived event table: key fields as columns for filtering,
  plus the full event kept as-is for detail views.
- **tenant.py** — a tenant (a company and its Wazuh group) and the things attached
  to it: its agents, contacts, and notification recipients.
- **user.py** — a user account, with its role and whether it is active.
