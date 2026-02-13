#!/usr/bin/env python3
"""
Snyk Export Vulnerabilities from Group

This script exports all vulnerabilities from the Snyk Export API for a given group,
saves the results as JSON and CSV files.
"""
import shutil
import os
import sys
import json
import logging
import argparse
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration class to hold all script parameters."""

    def __init__(self) -> None:
        self.GROUP_ID: str = ""
        self.DATE_FROM: str = ""
        self.DATE_TO: str = ""
        self.OUTPUT_FOLDER: str = "./results"
        self.API_URL: str = "https://api.snyk.io"
        self.API_VERSION: str = "2024-10-15"
        self.SNYK_TOKEN: str = ""

    def load(self) -> None:
        """Load configuration from command line arguments and environment variables."""
        parser = argparse.ArgumentParser(
            description="Export vulnerabilities from Snyk Group using the Export API."
        )
        parser.add_argument(
            "--group-id",
            required=True,
            help="Snyk Group ID (required)"
        )
        parser.add_argument(
            "--date-from",
            required=True,
            help="Start date in YYYY-MM-DD format (required)"
        )
        parser.add_argument(
            "--date-to",
            required=True,
            help="End date in YYYY-MM-DD format (required)"
        )
        parser.add_argument(
            "--output-folder",
            default="./results",
            help="Output folder for results (default: ./results)"
        )
        parser.add_argument(
            "--api-url",
            default="https://api.snyk.io",
            help="Snyk API URL (default: https://api.snyk.io)"
        )
        parser.add_argument(
            "--api-version",
            default="2024-10-15",
            help="Snyk API version (default: 2024-10-15)"
        )

        args = parser.parse_args()

        self.GROUP_ID = args.group_id
        self.DATE_FROM = args.date_from
        self.DATE_TO = args.date_to
        self.OUTPUT_FOLDER = args.output_folder
        self.API_URL = args.api_url
        self.API_VERSION = args.api_version
        self.SNYK_TOKEN = os.getenv("SNYK_TOKEN", "")

    def validate(self) -> None:
        """Validate that all required configuration is present and correctly formatted."""
        errors = []

        # Check required environment variable
        if not self.SNYK_TOKEN:
            errors.append("SNYK_TOKEN environment variable is not set")

        # Check required arguments
        if not self.GROUP_ID:
            errors.append("--group-id is required")

        # Validate date format (YYYY-MM-DD)
        date_pattern = r"^\d{4}-\d{2}-\d{2}$"
        
        if not self.DATE_FROM:
            errors.append("--date-from is required")
        elif not re.match(date_pattern, self.DATE_FROM):
            errors.append(f"--date-from must be in YYYY-MM-DD format, got: {self.DATE_FROM}")
        else:
            # Validate it's a valid date
            try:
                datetime.strptime(self.DATE_FROM, "%Y-%m-%d")
            except ValueError:
                errors.append(f"--date-from is not a valid date: {self.DATE_FROM}")

        if not self.DATE_TO:
            errors.append("--date-to is required")
        elif not re.match(date_pattern, self.DATE_TO):
            errors.append(f"--date-to must be in YYYY-MM-DD format, got: {self.DATE_TO}")
        else:
            # Validate it's a valid date
            try:
                datetime.strptime(self.DATE_TO, "%Y-%m-%d")
            except ValueError:
                errors.append(f"--date-to is not a valid date: {self.DATE_TO}")

        # Validate date range
        if self.DATE_FROM and self.DATE_TO:
            try:
                from_date = datetime.strptime(self.DATE_FROM, "%Y-%m-%d")
                to_date = datetime.strptime(self.DATE_TO, "%Y-%m-%d")
                if from_date > to_date:
                    errors.append("--date-from must be before or equal to --date-to")
            except ValueError:
                pass  # Already reported above

        if errors:
            raise ValueError("\n".join(errors))

    def get_date_from_iso(self) -> str:
        """Convert DATE_FROM to ISO format with time 00:00:00Z."""
        return f"{self.DATE_FROM}T00:00:00Z"

    def get_date_to_iso(self) -> str:
        """Convert DATE_TO to ISO format with time 23:59:59Z."""
        return f"{self.DATE_TO}T23:59:59Z"


console = Console()


def setup_logging(output_folder: str) -> logging.Logger:
    """Setup logging to both console and file."""
    # Create output folder if it doesn't exist
    Path(output_folder).mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger("snyk-export-vulns")
    logger.setLevel(logging.DEBUG)

    # Create log file with date in name
    log_filename = datetime.now().strftime("%Y%m%d") + ".log"
    log_filepath = Path(output_folder) / log_filename

    # File handler
    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)

    return logger


def get_headers(token: str) -> dict:
    """Get HTTP headers for API requests."""
    return {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }


def clear_output_folder(output_folder: str, logger: logging.Logger) -> None:
    """Clear the output folder."""
    if os.path.exists(output_folder):
        for filename in os.listdir(output_folder):
            file_path = os.path.join(output_folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                logger.warning(f"Failed to delete {file_path}: {e}")
    else:
        os.makedirs(output_folder, exist_ok=True)


def start_export(config: Config, logger: logging.Logger) -> str:
    """
    Start the export job by calling the Snyk Export API.
    
    Returns the export job ID.
    """
    url = f"{config.API_URL}/rest/groups/{config.GROUP_ID}/export?version={config.API_VERSION}"
    
    payload = {
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
                    "ISSUE_STATUS"
                ],
                "dataset": "issues",
                "filters": {
                    "introduced": {
                        "from": config.get_date_from_iso(),
                        "to": config.get_date_to_iso()
                    }
                },
                "formats": ["csv"],
                "url_expiration_seconds": 3600
            },
            "type": "resource"
        }
    }

    logger.info(f"Starting export job for group {config.GROUP_ID}")
    logger.debug(f"Export URL: {url}")
    logger.debug(f"Date range: {config.get_date_from_iso()} to {config.get_date_to_iso()}")

    try:
        response = requests.post(
            url,
            headers=get_headers(config.SNYK_TOKEN),
            json=payload,
            timeout=60,
            verify=False
        )
        response.raise_for_status()
        
        data = response.json()
        export_id = data["data"]["id"]
        
        logger.info(f"Export job started successfully with ID: {export_id}")
        return export_id

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error starting export: {e}")
        logger.error(f"Response: {e.response.text if e.response else 'No response'}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error starting export: {e}")
        raise
    except KeyError as e:
        logger.error(f"Unexpected response format: {e}")
        raise


def check_export_status(config: Config, export_id: str, logger: logging.Logger) -> Optional[dict]:
    """
    Check the status of an export job.
    
    Returns the full response data if the job is FINISHED, None otherwise.
    """
    url = f"{config.API_URL}/rest/groups/{config.GROUP_ID}/jobs/export/{export_id}?version={config.API_VERSION}"
    
    try:
        response = requests.get(
            url,
            headers=get_headers(config.SNYK_TOKEN),
            timeout=60,
            verify=False
        )
        response.raise_for_status()
        
        data = response.json()
        status = data.get("data", {}).get("attributes", {}).get("status", "")
        
        logger.debug(f"Export job status: {status}")
        
        if status == "FINISHED":
            return data
        
        return None

    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error checking export status: {e}")
        logger.error(f"Response: {e.response.text if e.response else 'No response'}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error checking export status: {e}")
        raise


def wait_for_export(config: Config, export_id: str, logger: logging.Logger) -> dict:
    """
    Wait for the export job to complete by polling the status endpoint.
    
    Returns the final response data when the job is FINISHED.
    """
    logger.info(f"Waiting for export job {export_id} to complete...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Waiting for export to complete...",
            total=None
        )
        
        poll_count = 0
        while True:
            poll_count += 1
            progress.update(task, description=f"[cyan]Checking export status (attempt {poll_count})...")
            
            result = check_export_status(config, export_id, logger)
            
            if result is not None:
                logger.info("Export job completed successfully")
                progress.update(task, description="[green]Export completed!")
                return result
            
            # Wait 1 second before next poll
            import time
            time.sleep(1)


def download_csv_files(results: list, output_folder: str, logger: logging.Logger) -> int:
    """
    Download all CSV files from the export results.
    
    Returns the number of files downloaded.
    """
    output_path = Path(output_folder)
    downloaded = 0
    
    logger.info(f"Downloading {len(results)} CSV file(s)...")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Downloading CSV files...",
            total=len(results)
        )
        
        for idx, result in enumerate(results, start=1):
            url = result.get("url")
            file_size = result.get("file_size", 0)
            row_count = result.get("row_count", 0)
            
            if not url:
                logger.warning(f"Skipping result {idx}: no URL provided")
                continue
            
            filename = f"csv_{idx}.csv"
            filepath = output_path / filename
            
            progress.update(
                task,
                description=f"[cyan]Downloading {filename} ({row_count} rows, {file_size} bytes)..."
            )
            
            try:
                response = requests.get(url, timeout=300, verify=False)
                response.raise_for_status()
                
                with open(filepath, "wb") as f:
                    f.write(response.content)
                
                logger.info(f"Downloaded {filename}: {row_count} rows, {file_size} bytes")
                downloaded += 1
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading {filename}: {e}")
            
            progress.advance(task)
        
        progress.update(task, description=f"[green]Downloaded {downloaded} CSV file(s)")
    
    return downloaded


def save_json_result(data: dict, output_folder: str, logger: logging.Logger) -> None:
    """Save the full JSON response to result.json."""
    output_path = Path(output_folder)
    filepath = output_path / "result.json"
    
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Saved JSON response to {filepath}")
        
    except IOError as e:
        logger.error(f"Error saving JSON result: {e}")
        raise


def main() -> int:
    """Main entry point for the script."""
    # Load and validate configuration
    config = Config()
    
    try:
        config.load()
        config.validate()
    except ValueError as e:
        console.print(f"[bold red]Configuration Error:[/bold red]\n{e}")
        return 1
    
    # Setup logging
    logger = setup_logging(config.OUTPUT_FOLDER)
    
    # Print header
    console.print("\n[bold blue]═══════════════════════════════════════════════════════════[/bold blue]")
    console.print("[bold white]         Snyk Export Vulnerabilities from Group            [/bold white]")
    console.print("[bold blue]═══════════════════════════════════════════════════════════[/bold blue]\n")
    
    console.print(f"[bold]Group ID:[/bold] [cyan]{config.GROUP_ID}[/cyan]")
    console.print(f"[bold]Date Range:[/bold] [cyan]{config.DATE_FROM}[/cyan] to [cyan]{config.DATE_TO}[/cyan]")
    console.print(f"[bold]Output Folder:[/bold] [cyan]{config.OUTPUT_FOLDER}[/cyan]")
    console.print(f"[bold]API URL:[/bold] [cyan]{config.API_URL}[/cyan]")
    console.print()
    
    logger.info("=" * 60)
    logger.info("Snyk Export Vulnerabilities - Starting")
    logger.info("=" * 60)
    logger.info(f"Group ID: {config.GROUP_ID}")
    logger.info(f"Date Range: {config.DATE_FROM} to {config.DATE_TO}")
    logger.info(f"Output Folder: {config.OUTPUT_FOLDER}")
    logger.info(f"API URL: {config.API_URL}")
    logger.info(f"API Version: {config.API_VERSION}")
    
    try:
        # Step 1: Start the export job
        # Clear the output folder before starting

        output_folder = config.OUTPUT_FOLDER

        step = 1

        console.print(f"[bold yellow]Step {step}:[/bold yellow] Clearing output folder...")
        step += 1
        clear_output_folder(output_folder, logger)
        console.print(f"[green]✓[/green] Output folder cleared\n")
        
        console.print(f"[bold yellow]Step {step}:[/bold yellow] Starting export job...")
        step += 1
        export_id = start_export(config, logger)
        console.print(f"[green]✓[/green] Export job started with ID: [cyan]{export_id}[/cyan]\n")

        # Step 2: Wait for the export to complete
        console.print(f"[bold yellow]Step {step}:[/bold yellow] Waiting for export to complete...")
        step += 1
        result_data = wait_for_export(config, export_id, logger)
        
        # Get summary info
        attributes = result_data.get("data", {}).get("attributes", {})
        total_rows = attributes.get("row_count", 0)
        results = attributes.get("results", [])
        
        console.print(f"[green]✓[/green] Export completed: [cyan]{total_rows}[/cyan] total rows in [cyan]{len(results)}[/cyan] file(s)\n")
        
        # Step 3: Save the JSON result
        console.print(f"[bold yellow]Step {step}:[/bold yellow] Saving JSON result...")
        step += 1
        save_json_result(result_data, config.OUTPUT_FOLDER, logger)
        console.print(f"[green]✓[/green] Saved result.json\n")
        
        # Step 4: Download CSV files
        console.print(f"[bold yellow]Step {step}:[/bold yellow] Downloading CSV files...")
        step += 1
        downloaded = download_csv_files(results, config.OUTPUT_FOLDER, logger)
        console.print(f"[green]✓[/green] Downloaded {downloaded} CSV file(s)\n")
        
        # Print summary
        console.print("[bold blue]═══════════════════════════════════════════════════════════[/bold blue]")
        console.print("[bold white]                        SUMMARY                           [/bold white]")
        console.print("[bold blue]═══════════════════════════════════════════════════════════[/bold blue]")
        console.print(f"[bold]Total Rows:[/bold] [green]{total_rows}[/green]")
        console.print(f"[bold]CSV Files:[/bold] [green]{downloaded}[/green]")
        console.print(f"[bold]Output Folder:[/bold] [cyan]{config.OUTPUT_FOLDER}[/cyan]")
        console.print("[bold blue]═══════════════════════════════════════════════════════════[/bold blue]\n")
        
        logger.info("=" * 60)
        logger.info("Export completed successfully")
        logger.info(f"Total rows: {total_rows}")
        logger.info(f"CSV files downloaded: {downloaded}")
        logger.info("=" * 60)
        
        return 0
        
    except requests.exceptions.HTTPError as e:
        console.print(f"\n[bold red]HTTP Error:[/bold red] {e}")
        if hasattr(e, 'response') and e.response is not None:
            console.print(f"[red]Response:[/red] {e.response.text}")
        logger.error(f"Script failed with HTTP error: {e}")
        return 1
        
    except requests.exceptions.RequestException as e:
        console.print(f"\n[bold red]Request Error:[/bold red] {e}")
        logger.error(f"Script failed with request error: {e}")
        return 1
        
    except Exception as e:
        console.print(f"\n[bold red]Unexpected Error:[/bold red] {e}")
        logger.exception("Script failed with unexpected error")
        return 1


if __name__ == "__main__":
    sys.exit(main())
