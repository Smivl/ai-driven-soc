# frontend/src

The dashboard the SOC team uses. It signs an analyst in, then shows live security
events, a per-tenant threat radar, and tenant settings, all reading from the
backend API and refreshing on a timer.

## Files at this level

- **main.tsx** — the entry point. Sets up routing, the data-fetching layer, and
  renders the app.
- **App.tsx** — the list of pages and their URLs. The login page is open; every
  other page sits behind a login check and inside the shared layout.

## Areas

- **pages/** — one file per screen: login, the dashboard radar, the active alerts
  list, a single event's detail, the tenants list, and one tenant's detail page.
- **components/** — shared pieces used by the pages: the app frame (sidebar,
  header, search), the notifications panel, and the login gate.
- **hooks/** — small wrappers around the API calls. Each one fetches or changes
  some data and keeps the screen up to date.
- **context/** — holds who is logged in and shares it with the whole app.
- **lib/** — the shared HTTP client (which attaches the login token) and small
  formatting helpers for severity, times, and search.
- **types/** — the TypeScript shapes for the data the backend returns, so the
  fields line up with the API.
