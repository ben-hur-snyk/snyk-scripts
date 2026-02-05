import os
import sys
import time
from typing import Dict, List
import argparse
import json
import requests
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()

class Config:
    def __init__(self) -> None:
        self.ORG_ID = ""
        self.API_VERSION = ""
        self.API_BASE_URL = ""
        self.SNYK_TOKEN = ""
        self.TARGETS_JSON_FILE = "targets.json"
        self.FAILED_TARGETS_JSON_FILE = "failed_targets.json"
        self.SUCCESSFUL_TARGETS_JSON_FILE = "successful_targets.json"

    def load(self):
        parser = argparse.ArgumentParser(description="Delete all targets in an Org.")
        parser.add_argument("--org-id", required=True, help="Snyk Organization ID")
        parser.add_argument("--api-version", default="2025-11-05", help="Snyk API version")
        parser.add_argument("--api-base-url", default="https://api.snyk.io", help="Snyk API base URL")
        args = parser.parse_args()

        self.ORG_ID = args.org_id
        self.API_VERSION = args.api_version
        self.API_BASE_URL = args.api_base_url
        self.SNYK_TOKEN = os.getenv("SNYK_TOKEN")
        

    def validate(self):
        missing_vars = []
        if not self.SNYK_TOKEN:
            missing_vars.append("SNYK_TOKEN")
        if not self.ORG_ID:
            missing_vars.append("ORG_ID")
        if missing_vars:
            raise ValueError(f"Missing required configuration variables: {', '.join(missing_vars)}")


console = Console()

config = Config()
config.load()
config.validate()


def get_headers():
    return {
        "Authorization": f"token {config.SNYK_TOKEN}",
        "Content-Type": "application/json",
    }


def load_targets() -> List[Dict]:
    url = f"{config.API_BASE_URL}/rest/orgs/{config.ORG_ID}/targets?version={config.API_VERSION}&exclude_empty=false&limit=100"

    targets = []
    has_next = True

    while has_next:
        try:
            response = requests.get(
                url, headers=get_headers(), timeout=30
            )
            response.raise_for_status()
            
            targets.extend(response.json().get("data", []))
            next_url = response.json().get("links", {}).get("next")
            has_next = next_url is not None

            url = f"{config.API_BASE_URL}{next_url}"

        except Exception as e:
            raise ValueError(f"Error fetching targets: {e}")

    return targets


def delete_target(target) -> bool:
    try:
        target_id = target["id"]
        url = f"{config.API_BASE_URL}/rest/orgs/{config.ORG_ID}/targets/{target_id}"
        params = {"version": config.API_VERSION}

        response = requests.delete(
            url, headers=get_headers(), params=params, timeout=30
        )
        response.raise_for_status()

        return 200 <= response.status_code < 300, None
    except Exception as e:
        return False, e


def main():
    console.print(f"Starting bulk target deletion for org: [bold cyan]{config.ORG_ID}[/bold cyan]\n")

    targets = []
    successful = 0
    failed = 0

    targets = load_targets()
    successful_targets = []
    failed_targets = []

    for target in targets:
        target_id = target["id"]
        target_name = target["attributes"]["display_name"]

        console.print(f"Deleting target: {target_name} ({target_id})")

        success, error = delete_target(target)
        if success:
            console.print(f"✅ Successfully deleted target: {target_name} ({target_id})")
            successful += 1
            successful_targets.append(target)
        else:
            console.print(f"❌ Failed to delete target: {target_name} ({target_id})")
            console.print(f"Error: {error}")
            failed += 1
            failed_targets.append(target)

    with open(config.TARGETS_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    with open(config.SUCCESSFUL_TARGETS_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(successful_targets, f, ensure_ascii=False, indent=2)
    with open(config.FAILED_TARGETS_JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(failed_targets, f, ensure_ascii=False, indent=2)

    console.print(f"\n{'=' * 50}")
    console.print("[bold white]SUMMARY[/bold white]")
    console.print(f"{'=' * 50}")
    console.print(f"Total targets: [bold yellow]{len(targets)}[/bold yellow] [bold white]{config.TARGETS_JSON_FILE}[/bold white]")
    console.print(f"Successfully deleted: [bold green]{successful}[/bold green] [bold white]{config.SUCCESSFUL_TARGETS_JSON_FILE}[/bold white]")
    console.print(f"Failed: [bold red]{failed}[/bold red] [bold white]{config.FAILED_TARGETS_JSON_FILE}[/bold white]")
    console.print(f"{'=' * 50}\n")

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
