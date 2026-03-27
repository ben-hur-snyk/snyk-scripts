# Import target in Snyk if not exists


Create a nodejs script that check if a target exist in Snyk. If not, import it.

## Variables

The script require some variables to work:

- SNYK_TOKEN: the authentication token
- SNYK_ORG_ID: the id of the organization (uuid)
- SNYK_INTEGRATION_ID: the Id of SCM integration (uuid)
- REPOSITORY_URL: the url encoded of the repository (example: https%3A%2F%2Fgitlab.com.br%2Fbenhur.snyk.demo-group%2Fmulti-stack-demo)


## Check if target exists

This is the request to check if it exists:

```sh
curl --request GET \
  --url 'https://api.snyk.io/rest/orgs/$SNYK_ORG_ID/targets?version=2024-10-15&count=true&url=$REPOSITORY_URL' \
  --header 'authorization: $SNYK_TOKEN'
```

This is the response:

```json
{
  "jsonapi": {
    "version": "1.0"
  },
  "data": [
    {
      "id": "564b6a5b-5281-4417-8eec-6b44aee4732e",
      "type": "target",
      "attributes": {
        "display_name": "benhur.snyk.demo-group/multi-stack-demo",
        "url": "https://gitlab.com/benhur.snyk.demo-group/multi-stack-demo",
        "is_private": true,
        "created_at": "2025-11-12T19:49:04.530Z"
      },
      "relationships": {
        "organization": {
          "data": {
            "type": "organization",
            "id": "65523c0b-3a89-4f55-a819-11c497a7c0d3"
          }
        },
        "integration": {
          "data": {
            "type": "integration",
            "id": "75bc0914-7d0c-4fc4-bbd9-0defb11d92a2",
            "attributes": {
              "integration_type": "gitlab"
            }
          }
        }
      }
    }
  ],
  "links": {},
  "meta": {
    "count": 2
  }
}
```

If the meta.count equals 0. It does not exist.


## Import

To import a project, we use this API:

```sh
curl --request POST \
  --url https://api.snyk.io/v1/org/$ORG_ID/integrations/$INTEGRATION_ID/import?version=2024-10-15 \
  --header 'authorization: token $SNYK_TOKEN' \
  --header 'content-type: application/json' \
  --data '{
  "target": {
    "owner": "$REPO_OWNER",
    "name": "$REPO_NAME",
    "branch": "$REPO_BRANCH"
  }
}'
```

To fulfil the REPO_ vars, use the repository URL parts:

(Example of `https://gitlab.com.br/benhur.snyk.demo-group/multi-stack-demo`)

- REPO_OWNER: `benhur.snyk.demo-group`
- REPO_NAME: `multi-stack-demo`
- REPO_BRANCH: `main`