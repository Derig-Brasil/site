# Development Guide

This document outlines how to set up your environment and start developing for the DÉRIG website. You can choose between using a pre-configured Dev Container or setting up the environment natively on your machine.

## Option 1: Dev Container (Recommended)

This method ensures you have the exact environment needed without installing dependencies locally.

### Prerequisites
- VS Code with the **"Dev Containers"** extension.
- Docker or a compatible container runtime.

### Steps
1. Open this folder in VS Code.
2. When prompted, select **"Reopen in Container"**. 
   - Alternatively: Open the Command Palette (Ctrl+Shift+P) → **"Dev Containers: Reopen in Container"**.
3. Once inside, follow the **Starting Development** steps below.

## Option 2: Local Setup (Native)

Use this if you prefer to run the project directly on your operating system.

### Prerequisites
- **Node.js**: Version 20.x or higher is recommended.
- **npm**: Usually comes with Node.js.
- **Wrangler**: Authenticated with your Cloudflare account (`npx wrangler login`).

### Steps
1. Clone the repository and navigate to the root folder.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Follow the **Starting Development** steps below.

## Starting Development

Regardless of your setup method, use these commands to start working:

1. **Build and Watch**: In one terminal, start Eleventy in watch mode to automatically rebuild the static files when they change:
   ```bash
   npm run watch
   ```

2. **Run Dev Server**: In a second terminal, start Wrangler to serve the built site and handle API requests:
   ```bash
   npm run dev:worker
   ```

- Open [http://localhost:8787](http://localhost:8787) to view the site.

## Scripts for Development

- `npm run build` – Build the site with Eleventy into `_site/`.
- `npm run watch` – Rebuild on changes using Eleventy’s watch mode.
- `npm run serve` – Run Eleventy’s dev server on http://localhost:8080 (Note: this does **not** run the Worker/API).
- `npm run dev:worker` – Start Wrangler dev (serves `_site/` and `/api/*`) at http://localhost:8787.

## Development Notes

- **Local flow**: Keep `watch` running to update `_site/` on changes, and run `dev:worker` to serve via the Worker so you can test the contact API and other backend features locally.

