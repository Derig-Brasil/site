# Dev Container for Eleventy + Cloudflare Workers (Wrangler)
FROM node:20-bullseye

# Install global tooling
RUN npm i -g @11ty/eleventy wrangler@latest

# Create workspace directory
WORKDIR /workspaces/app

# Default shell
SHELL ["/bin/bash", "-lc"]

# Non-root convenience (optional)
# RUN useradd -ms /bin/bash nodeuser && chown -R nodeuser:nodeuser /workspaces && USER nodeuser

# Cache layer for dependencies (optional)
# Using VS Code devcontainers, the workspace is bind-mounted at runtime.
# Avoid copying sources during image build to keep the image slim.
