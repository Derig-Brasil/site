# Deployment Guide

This document explains how the DÉRIG website is deployed to Cloudflare.

## Automated Deployment (Recommended)

The project is integrated with **GitHub and Cloudflare**. This is the primary and recommended deployment method.

- **Production**: Any push or merged Pull Request to the `main` branch automatically triggers a build and deployment to the production environment.
- **Preview/Test**: Depending on the Cloudflare configuration, pushes to other branches may trigger "Preview" deployments for testing.

To deploy changes:
1. Commit your changes to a branch.
2. Open a Pull Request to `main`.
3. Once reviewed and merged, Cloudflare will automatically build the site using `npm run build` and deploy the updated Worker and static assets.

## Manual Deployment

Manual deployment can be used for local testing of the production build or in emergency situations.

1. **Authenticate** with Cloudflare:

```bash
wrangler login
```

2. **Build** the static site:

```bash
npm run build
```

3. **Deploy** the Worker:

```bash
npm run deploy
```

The `[assets]` section in `wrangler.toml` (or `wrangler.jsonc`) points to `_site/`. Wrangler uploads these static assets, and the Worker defined in `worker/index.js` handles routing and API endpoints.

## Deployment & Database Scripts

- `npm run deploy` – Deploy the Worker to Cloudflare (default/production environment).
- `npm run migrate:prod` – Apply D1 migrations to the `site-prod` database (remote).
- `npm run deploy:with-migrations` – Run production migrations then deploy to Cloudflare.
- `npm run migrate:test` – Apply D1 migrations to the `site-test` database using `--env test` (remote).
- `npm run deploy:test` – Build, run test migrations, then deploy with `--env test`.

