# Export Vuln Status Report from ORG

This script use the [Export API](https://docs.snyk.io/snyk-api/reference/export#post-orgs-org_id-export) to get all the vulnerabilities from an organization and resume as status count.

The result of the script will be a json like this:

```json
{
    "date": "2025-10-31",
    "org_id": "65523c0b-3a89-4f55-a819-11c497a7c0d3",
    "from_date": "2025-01-01T00:00:00Z",
    "to_date": "2025-12-31T23:59:59Z",
    "report": {
        "critical": {
            "total": 1018,
            "open": 995,
            "ignored": 4,
            "resolved": 19
        },
        "high": {
            "total": 4316,
            "open": 4026,
            "ignored": 243,
            "resolved": 47
        },
        "medium": {
            "total": 4669,
            "open": 4402,
            "ignored": 199,
            "resolved": 68
        },
        "low": {
            "total": 8399,
            "open": 8149,
            "ignored": 106,
            "resolved": 144
        }
    }
}
```

It will also save all csv files to into the `./csv` folder.


## Running

Set the SNYK_TOKEN env var with your Snyk PAT or Service Account token.

```sh
export SNYK_TOKEN=my-snyk-token
```

Run with your org id:

```sh
go run main.go MY_ORG_ID DATE_FROM DATE_TO 

# example
go run main.go 65523c0b-3a89-4f55-a819-11c497a7c0d3 2025-01-01 2025-12-31
```