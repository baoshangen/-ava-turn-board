# AVA Turn Board

Shared salon turn board for phones and laptops. It includes:

- Seven daily boards with up to 15 turns
- Technician arrival ordering
- Service selection and visual status colors
- Compact and expanded board views
- Per-day reset controls
- Salon login with optional 30-day sessions
- Conflict-aware synchronization between devices

## Development

```bash
npm install
npm run build
node --test tests/auth.mjs
```

## Hosting

This project requires a serverless Worker and a D1-compatible database. GitHub Pages alone cannot run the login, database, or multi-device synchronization features.

Configure these runtime bindings before deploying:

- `DB`: D1 database binding
- `OWNER_EMAIL`: email allowed to initialize or change the salon account

Never commit passwords, session tokens, or production database contents.
