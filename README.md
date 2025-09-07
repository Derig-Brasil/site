# DÉRIG website

## Features

- __Eleventy__ static site generator
- __Cloudflare Worker__ serving built assets and handling `/api/*`
- __MailChannels__ email delivery (no external server required)
- __Dev Container__ for development without Node installed locally

## Prereqs

- VS Code with the "Dev Containers" extension, or any editor that can open a Dev Container
- A Cloudflare account with Wrangler authenticated (`wrangler login` inside the container)

## Getting Started (Dev Container)

1. Open this folder in VS Code.
2. When prompted, "Reopen in Container". Alternatively: Command Palette → "Dev Containers: Reopen in Container".
3. Inside the container terminal:

```bash
npm install
npm run build        # builds Eleventy to _site/
```

4. In one terminal, watch Eleventy changes:

```bash
npm run watch
```

5. In another terminal, start the Worker locally:

```bash
npm run dev:worker   # serves _site/ as static assets and /api/* endpoint
```

- Open http://localhost:8787 to view the site (Wrangler default dev port).

## Deploy

1. Authenticate:

```bash
wrangler login
```

2. Build the site:

```bash
npm run build
```

3. Deploy the Worker:

```bash
npm run deploy
```

- The `[assets]` section in `wrangler.toml` points to `_site/`, so Wrangler will upload your static assets and the Worker `worker/index.js` will handle the API.

## Scripts

- `npm run build` – Build the site with Eleventy into `_site/`.
- `npm run watch` – Rebuild on changes using Eleventy’s watch mode.
- `npm run serve` – Run Eleventy’s dev server on http://localhost:8080 (does not run the Worker/API).
- `npm run dev:worker` – Start Wrangler dev (serves `_site/` and `/api/*`) at http://localhost:8787.
- `npm run deploy` – Deploy the Worker to Cloudflare (default/prod environment).
- `npm run migrate:prod` – Apply D1 migrations to the `prod-db` database (remote).
- `npm run deploy:with-migrations` – Run prod migrations then deploy to Cloudflare.
- `npm run migrate:test` – Apply D1 migrations to the `site-test` database using `--env test` (remote).
- `npm run deploy:test` – Build, run test migrations, then deploy with `--env test`.

## Notes

- Local dev flow: keep `watch` running to update `_site/` on changes, and run `dev:worker` to serve via the Worker so you can test the contact API.
