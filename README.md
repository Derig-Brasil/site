# DÉRIG Website

## Tech Stack

- **Eleventy**: Static site generator.
- **Cloudflare Workers**: Serves static assets and handles `/api/*` endpoints.
- **MailChannels**: Email delivery.

## Documentation

For detailed information on how to work with this project, please refer to the following guides:

- 🛠️ **[Development Guide](./docs/development.md)**: Prerequisites, local setup, and development scripts.
- 🚀 **[Deployment Guide](./docs/deployment.md)**: Instructions for deploying to production and test environments.
- ⚙️ **[Configuration Guide](./docs/configuration.md)**: Managing environment variables, secrets, and Cloudflare KV settings.

## Quick Start (Dev Container)

1. Open this folder in VS Code.
2. Select **"Reopen in Container"** when prompted.
3. Run `npm install` and `npm run build`.
4. Run `npm run watch` in one terminal and `npm run dev:worker` in another.
5. Visit [http://localhost:8787](http://localhost:8787).

