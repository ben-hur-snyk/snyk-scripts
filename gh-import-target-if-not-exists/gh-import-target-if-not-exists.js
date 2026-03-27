#!/usr/bin/env node
/**
 * Check if a repository target exists in Snyk; if not, import it via the SCM integration.
 */

import dotenv from "dotenv";
dotenv.config();

const API_BASE = "https://api.snyk.io";
const REST_VERSION = "2024-10-15";
const IMPORT_VERSION = "2024-10-15";

function decodeRepositoryUrl(raw) {
  if (!raw || typeof raw !== "string") {
    return "";
  }
  try {
    return decodeURIComponent(raw.trim());
  } catch {
    return raw.trim();
  }
}

function parseRepoFromUrl(repositoryUrl) {
  let parsed;
  try {
    parsed = new URL(repositoryUrl);
  } catch {
    throw new Error(`Invalid repository URL: ${repositoryUrl}`);
  }

  const segments = parsed.pathname
    .split("/")
    .map((s) => s.trim())
    .filter(Boolean);

  if (segments.length < 2) {
    throw new Error(
      "Repository URL path must include owner and project name (at least two segments), e.g. https://host/group/project"
    );
  }

  const name = segments.pop();
  const owner = segments.join("/");
  return { owner, name };
}

function requireEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return String(v).trim();
}

async function fetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  if (!res.ok) {
    const detail =
      typeof body === "object" && body !== null
        ? JSON.stringify(body)
        : String(body ?? res.statusText);
    throw new Error(`HTTP ${res.status} ${res.statusText}: ${detail}`);
  }
  return body;
}

async function targetExists(token, orgId, repositoryUrlEncodedForQuery) {
  const params = new URLSearchParams({
    version: REST_VERSION,
    count: "true",
    url: repositoryUrlEncodedForQuery,
  });
  const url = `${API_BASE}/rest/orgs/${orgId}/targets?${params.toString()}`;
  console.info(`[INFO] Checking if target exists for URL: ${url}`);
  const data = await fetchJson(url, {
    headers: {
      Authorization: `token ${token}`,
      Accept: "application/vnd.api+json",
    },
  });
  const count = data?.meta?.count;
  const exists = typeof count === "number" && count > 0;
  console.info(`[INFO] Target ${exists ? "exists" : "does not exist"} for URL: ${repositoryUrlEncodedForQuery}`);
  return exists;
}

async function importTarget(token, orgId, integrationId, owner, name, branch) {
  const params = new URLSearchParams({ version: IMPORT_VERSION });
  const url = `${API_BASE}/v1/org/${orgId}/integrations/${integrationId}/import?${params.toString()}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `token ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      target: {
        owner,
        name,
        branch,
      },
    }),
  });
  const text = await res.text();
  if (res.status !== 201) {
    let detail = text || res.statusText;
    if (text) {
      try {
        const parsed = JSON.parse(text);
        if (typeof parsed === "object" && parsed !== null) {
          detail = JSON.stringify(parsed);
        }
      } catch {
        /* keep raw text */
      }
    }
    throw new Error(`Import failed: expected HTTP 201, got ${res.status}: ${detail}`);
  }
}

async function main() {
  const token = requireEnv("SNYK_TOKEN");
  const orgId = requireEnv("SNYK_ORG_ID");
  const integrationId = requireEnv("SNYK_INTEGRATION_ID");
  const rawRepoUrl = requireEnv("REPOSITORY_URL");

  const decodedUrl = decodeRepositoryUrl(rawRepoUrl);
  const branch = (process.env.REPO_BRANCH || "main").trim() || "main";

  const { owner, name } = parseRepoFromUrl(decodedUrl);

  const exists = await targetExists(token, orgId, decodedUrl);
  if (exists) {
    process.exit(0);
  }

  console.info(`[INFO] Importing target: owner=${owner} name=${name} branch=${branch}`);
  await importTarget(token, orgId, integrationId, owner, name, branch);
  console.info("[SUCCESS] Import succeeded (HTTP 201).");
}

main().catch((err) => {
  console.error("[ERROR] " + (err instanceof Error ? err.message : err));
  process.exit(1);
});
