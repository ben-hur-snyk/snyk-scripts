# Snyk Export Vulns from Group


## Description

Create a single python script that export all the vulnerabilities from the export API, save the results as JSON and CSV, then show a chart in streamlit for it.

Follow the specification:

## Specification

### Run the script

To run the script, it should execute:

```
python3 snyk-export-vulns-grpup.py --group-id=<the group id> --date-from=YYYY-MM-DD --date-to=YYYY-MM-DD --output-folder=./results --api-url=https://api.snyk.io --api-version=2024-10-15
```

It should require a SNYK_TOKEN as environment variable.

The --group-id is required
The --date-from is required
The --date-to is required
The --output-folder is optional, defaults to ./results
The --api-url is optional, default to https://api.snyk.io
The --api-version is optional, defaults to 2024-10-15

Should validate the format and if the required parameters was provided.


### Export the issues

#### Start the Export
To export the issues, it should consume this API:

```
curl --request POST \
  --url '$API_URL/rest/groups/$GROUP_ID/export?version=2024-10-15' \
  --header 'authorization: $SNYK_TOKEN' \
  --header 'content-type: application/json' \
  --data '{
  "data": {
    "attributes": {
      "columns": [
        "GROUP_PUBLIC_ID",
        "ORG_PUBLIC_ID",
        "ISSUE_SEVERITY_RANK",
        "ISSUE_SEVERITY",
        "SCORE",
        "PROBLEM_TITLE",
        "CVE",
        "CWE",
        "PROJECT_NAME",
        "PROJECT_URL",
        "FIRST_INTRODUCED",
        "PRODUCT_NAME",
        "ISSUE_URL",
        "ISSUE_STATUS",
        "ISSUE_TYPE"
      ],
      "dataset": "issues",
      "filters": {
        "introduced": {
          "from": "$DATE_FROM",
          "to": "$DATE_TO"
        }
      },
      "formats": [
        "csv"
      ],
      "url_expiration_seconds": 3600
    },
    "type": "resource"
  }
}'
```

The $API_URL should come from --api-url
The $GROUP_ID should come from --group-id
The $SNYK_TOKEN should come from env vars
The $DATE_FROM should come from the --date-from, but be in this format: 2026-01-01T00:00:00Z (with time 0)
The $DATE_TO should come from the --date-to, but be in this format: 2026-01-31T23:59:59Z (with last time of the day)

The response of this API is in this format:

```
{
  "data": {
    "attributes": {
      "created": "2026-02-12T20:09:42.693"
    },
    "id": "94f572f3-f17d-4d8d-ac55-44a8a034a6a9",
    "links": {
      "self": "/groups/a1cbf11b-aa99-4434-b4e7-1bb47fc86db1/jobs/export/94f572f3-f17d-4d8d-ac55-44a8a034a6a9?version=2024-10-15"
    },
    "type": "export"
  }
}
```

The ID should be stored in memory to obtain the results in the next call.

#### Get the export status

Each second we need to make a request to check if the status of the export is FINISHED using this request:

```
curl --request GET \
  --url 'https://api.snyk.io/rest/groups/$GROUP_ID/jobs/export/$EXPORT_ID?version=2024-10-15' \
  --header 'authorization: $SNYK_TOKEN'
```

The $EXPORT_ID should be the ID obtained in the previous step.


We need to check if in the response if:

1. The request is successfull (status code 200)
2. The result body json has this property value: $.data.attributes.status == "FINISHED"

If the status returns "ERROR", show an error message and exit the program.

If yes, we can look to the same response to start save the results.


#### Save the results

Save all the results mentioned to the --output-folder param.

Save the json response as result.json

In the response we have this structure:

```json
{
  "data": {
    "attributes": {
      "results": [
        {
          "url": "https://snyk-export-polaris-prod-mt-gcp-1.storage.googleapis.com/5b4a3f0c-22ad-4875-973f-1ff5d355c220/data_1_1_0.csv?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=k69100000%40gcpuseast4-eea5.iam.gserviceaccount.com%2F20260212%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20260212T200947Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host&X-Goog-Signature=457a6239116e4c8e6de7754cf0c7e528947e14c9294dc4704d8683a55d8aa8277a5b037242ed946432d594ac43e7bf4683a48bcbe50dd4ca12b877e56ec0b9c400c1ecdc9dc8e58ae29294a100f97906604cc519e39a387f9a2376792120040155dad14fcdb6316591fd91c33aeffccfc7a5eda1df98f51892ebc1f65d14af9441e4899a5d6d657c389d54be0e34ff8e214ba3f307e635160c9c8788b0eed642b537d79cf51abfe05dddc827b308999efb4e5d9a3db1882b9cac0b63e9089d6ce5f2fef3946a9624c50dd6426805e7a9309fa0bd3638460fdd3a72ffecf88f6cf9ab6174658d32973e9f7029549f5853b01165c02a5a0e66613bc0ea4248b0ae",
          "file_size": 1328,
          "row_count": 3
        }
      ],
      "row_count": 1061,
      "status": "FINISHED"
    },
    "id": "94f572f3-f17d-4d8d-ac55-44a8a034a6a9",
    "type": "export"
  },
  "links": {
    "self": "/groups/a1cbf11b-aa99-4434-b4e7-1bb47fc86db1/export/94f572f3-f17d-4d8d-ac55-44a8a034a6a9?version=2024-10-15"
  }
}
```

For each URL in results, download the csv and save it as csv_$num.csv (where the $num is an incremental counter).


#### Generate Results Review


Read all the CSVs in the output folder.

The CSV has this format:

```
"SCORE","CVE","CWE","FIRST_INTRODUCED","PROJECT_NAME","PROJECT_URL","GROUP_PUBLIC_ID","ORG_PUBLIC_ID","PRODUCT_NAME","ORG_DISPLAY_NAME","ISSUE_SEVERITY","PROBLEM_TITLE","ISSUE_URL","ISSUE_STATUS","GROUP_SLUG"
110,"[""CVE-2025-65945""]","[""CWE-347""]","2025-12-05 21:14:01.949","juice-shop","https://app.snyk.io/org/ben-hur.ottsnyk.io/project/240148ae-8c9a-424f-8b3e-402921423cc7","a1cbf11b-aa99-4434-b4e7-1bb47fc86db1","65523c0b-3a89-4f55-a819-11c497a7c0d3","Snyk Open Source","default-org","High","Improper Verification of Cryptographic Signature","https://app.snyk.io/org/ben-hur.ottsnyk.io/project/240148ae-8c9a-424f-8b3e-402921423cc7#issue-SNYK-JS-JWS-14188253","Open","ben-demo-group-Wns7Y4dN3sPrHJCJ86Zpm4"

```

For each ISSUE_STATUS, an csv should be generated with the name "summary-$ISSUE_STATUS.csv"

This csv should contain these columns: ORG_DISPLAY_NAME, CRITICAL, HIGH, MEDIUM, LOW

Group all the results by org and count every issue by severity.

At the end, display the results in a table. One table per status.


## Technical Requirements

* The script should be in python
* Should use the rich library to add colors and spinners: https://github.com/Textualize/rich
* Should log all steps and errors to a YYYYMMDD.log file in the output folder
