# Delete All Org Targets

A Python CLI tool to bulk delete all targets in a Snyk organization using the Snyk REST API.

## Overview

This tool fetches all targets from a specified Snyk organization and deletes them one by one. It provides detailed progress output and generates JSON files tracking successful and failed deletions.

## Prerequisites

- Python 3.8+
- A Snyk API token with permissions to delete targets
- The Organization ID of the Snyk org you want to clean up

## Setup

### 1. Clone and navigate to the project

```bash
cd delete-all-org-targets
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate     # On Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```bash
SNYK_TOKEN=your_snyk_api_token_here
```

You can also export the environment variable directly:

```bash
export SNYK_TOKEN=your_snyk_api_token_here
```

## Usage

### Basic usage

```bash
python delete_all_org_targets.py --org-id YOUR_ORG_ID
```

### With custom API version (OPTIONAL)

```bash
python delete_all_org_targets.py --org-id YOUR_ORG_ID --api-version 2024-06-21
```

### With custom API base URL (for regional deployments) (OPTIONAL, default https://api.snyk.io)

```bash
# US2 datacenter
python delete_all_org_targets.py --org-id YOUR_ORG_ID --api-base-url https://api.us.snyk.io

# EU datacenter
python delete_all_org_targets.py --org-id YOUR_ORG_ID --api-base-url https://api.eu.snyk.io
```

### Command Line Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--org-id` | Yes | - | Snyk Organization ID |
| `--api-version` | No | `2025-11-05` | Snyk REST API version |
| `--api-base-url` | No | `https://api.snyk.io` | Snyk API base URL |

## Output Files

After execution, the tool generates three JSON files:

| File | Description |
|------|-------------|
| `targets.json` | All targets found in the organization |
| `successful_targets.json` | Targets that were successfully deleted |
| `failed_targets.json` | Targets that failed to delete |

## Example Output

```
Starting bulk target deletion for org: a1b2c3d4-e5f6-7890-abcd-ef1234567890

Deleting target: my-repo (target-id-123)
✅ Successfully deleted target: my-repo (target-id-123)
Deleting target: another-repo (target-id-456)
✅ Successfully deleted target: another-repo (target-id-456)

==============================
SUMMARY
==============================
Total targets: 2 targets.json
Successfully deleted: 2 successful_targets.json
Failed: 0 failed_targets.json
==============================
```

## Finding Your Organization ID

1. Log in to your Snyk account
2. To to your Org settings
3. Copy the Organization ID value

## Getting a Snyk Service Account Token

1. Log in to your Snyk account
2. To to your Org settings > Service Accounts
3. Create a service account API token

https://docs.snyk.io/implementation-and-setup/enterprise-setup/service-accounts

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | All targets deleted successfully |
| `1` | One or more targets failed to delete |

## Troubleshooting

### "Missing required configuration variables: SNYK_TOKEN"

Ensure your `.env` file exists and contains `SNYK_TOKEN`, or export it as an environment variable.

### "Missing required configuration variables: ORG_ID"

The `--org-id` argument is required. Make sure to provide it when running the script.

## License

MIT
