# api

The HTTP routes the dashboard calls. Everything here is thin: each route checks
who is asking, calls a service to do the real work, and returns the result.
All routes live under /api/v1.

## Files

- **deps.py** — shared login checks. One helper resolves the access token to the
  current user, another only lets admins through. Routes attach these to require
  a login or admin rights.
- **v1/auth.py** — log in with a username and password to get an access token,
  plus a small route to return the current user.
- **v1/events.py** — read the live events and the saved history, mark an event
  resolved, and clear the live list.
- **v1/tenants.py** — view and edit tenants, their contacts, and their
  notification recipients, plus the latest AI assessment per tenant.
- **v1/users.py** — admin-only user management: list, create, and activate or
  deactivate accounts.
