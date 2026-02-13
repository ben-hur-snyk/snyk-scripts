# Snyk Export Vulnerabilities from Group

Export vulnerabilities from a Snyk group for a date range using the Snyk Export API. Results are saved as JSON and CSV files.

## Prerequisites

- **Python 3** (3.8+)
- **Snyk API token** with access to the group you want to export from

## Setup

### 1. Clone or navigate to the project

```bash
cd export-vulns-group
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Set your Snyk API token

The script requires `SNYK_TOKEN` as an environment variable.

**Option A – export for the current shell:**

```bash
export SNYK_TOKEN="your-snyk-api-token"
```

**Option B – use a `.env` file (loaded automatically):**

Create a `.env` file in the project directory:

```
SNYK_TOKEN=your-snyk-api-token
```

Do not commit `.env` or your token to version control.

## Running the script

### Required arguments

| Argument       | Description                          |
|----------------|--------------------------------------|
| `--group-id`   | Snyk Group ID                        |
| `--date-from`  | Start date in `YYYY-MM-DD` format    |
| `--date-to`    | End date in `YYYY-MM-DD` format      |

### Optional arguments

| Argument          | Default                | Description                    |
|-------------------|------------------------|--------------------------------|
| `--output-folder` | `./results`            | Directory for output files    |
| `--api-url`       | `https://api.snyk.io`  | Snyk API base URL             |
| `--api-version`   | `2024-10-15`           | API version                   |

### Example

```bash
python3 snyk-export-vulns-group.py \
  --group-id=your-group-id \
  --date-from=2025-01-01 \
  --date-to=2025-01-31 \
  --output-folder=./results
```

With custom API URL and version:

```bash
python3 snyk-export-vulns-group.py \
  --group-id=your-group-id \
  --date-from=2025-01-01 \
  --date-to=2025-01-31 \
  --output-folder=./results \
  --api-url=https://api.snyk.io \
  --api-version=2024-10-15
```

### Help

```bash
python3 snyk-export-vulns-group.py --help
```

## Output

All files are written to the folder given by `--output-folder` (default: `./results`):

| File           | Description                                      |
|----------------|--------------------------------------------------|
| `result.json`  | Full API response (export metadata and result URLs) |
| `csv_1.csv`, `csv_2.csv`, … | Exported vulnerability data (one file per result chunk) |
| `YYYYMMDD.log` | Log file for the run (date of execution)         |

The script will create the output directory if it does not exist.

## Finding your Group ID

In the Snyk UI: open your **Group** settings. The Group ID appears in the URL or in the group settings page (e.g. `https://app.snyk.io/group/<group-id>`).

## Troubleshooting

- **`SNYK_TOKEN environment variable is not set`**  
  Set `SNYK_TOKEN` (see [Set your Snyk API token](#4-set-your-snyk-api-token)) or ensure your `.env` is in the script’s working directory.

- **`--date-from` / `--date-to` must be in YYYY-MM-DD format**  
  Use dates like `2025-01-01`. The script validates that the values are valid calendar dates.

- **HTTP 401 / 403**  
  Check that your token is valid and has access to the given group.

- **Export never finishes**  
  Large date ranges or groups can take longer. The script polls every second; check the log file in the output folder for details.
