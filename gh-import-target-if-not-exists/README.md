# gh-import-target-if-not-exists

Node script that checks whether a repository is already a **target** in your Snyk organization. If it is not, it **imports** it through your configured SCM integration (for example GitHub).

## Requirements

- Node.js 18 or newer
- A Snyk API token, org ID, and SCM integration ID (see [Environment variables](#environment-variables))

## Setup

```bash
cd gh-import-target-if-not-exists
npm install
```

Copy `.env.example` to `.env` and fill in values for local runs.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SNYK_TOKEN` | Yes | Snyk API token |
| `SNYK_ORG_ID` | Yes | Organization ID (UUID) |
| `SNYK_INTEGRATION_ID` | Yes | SCM integration ID (UUID) for the Git host where the repo lives |
| `REPOSITORY_URL` | Yes | Repository URL (plain or percent-encoded; the script decodes when needed) |
| `REPO_BRANCH` | No | Branch to import (default: `main`) |

## Local usage

```bash
export SNYK_TOKEN=…
export SNYK_ORG_ID=…
export SNYK_INTEGRATION_ID=…
export REPOSITORY_URL='https://github.com/my-org/my-repo'
export REPO_BRANCH=main   # optional

node gh-import-target-if-not-exists.js
```

Exit code `0` means the target already existed or import succeeded; non-zero means an error.

## GitHub Actions

Store sensitive values as repository or organization **secrets**. The workflow below assumes this directory (or a copy of it) exists in the repository at `gh-import-target-if-not-exists/`.

Create these secrets:

- `SNYK_TOKEN`
- `SNYK_ORG_ID`
- `SNYK_INTEGRATION_ID`

`REPOSITORY_URL` and `REPO_BRANCH` are taken from the workflow run (current repo and branch). Adjust paths if your script lives elsewhere.

```yaml
name: Snyk import target if missing

on:
  workflow_dispatch:
  push:
    branches:
      - main

jobs:
  import-if-needed:
    runs-on: ubuntu-latest
    permissions:
      contents: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Node
        uses: actions/setup-node@v4
        with:
          node-version: "20"
          cache: npm
          cache-dependency-path: gh-import-target-if-not-exists/package-lock.json

      - name: Install dependencies
        working-directory: gh-import-target-if-not-exists
        run: npm ci

      - name: Import repository into Snyk if not already a target
        working-directory: gh-import-target-if-not-exists
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
          SNYK_ORG_ID: ${{ secrets.SNYK_ORG_ID }}
          SNYK_INTEGRATION_ID: ${{ secrets.SNYK_INTEGRATION_ID }}
          REPOSITORY_URL: ${{ github.server_url }}/${{ github.repository }}
          REPO_BRANCH: ${{ github.ref_name }}
        run: node gh-import-target-if-not-exists.js
```

For a **scheduled** or **manual** run that should always target `main` regardless of the triggering ref, set `REPO_BRANCH: main` instead of `github.ref_name`.
