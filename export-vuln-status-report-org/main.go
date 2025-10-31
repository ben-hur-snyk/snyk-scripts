package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type ExportRequest struct {
	Data struct {
		Attributes struct {
			Columns []string `json:"columns"`
			Dataset string   `json:"dataset"`
			Filters struct {
				Introduced struct {
					From string `json:"from"`
					To   string `json:"to"`
				} `json:"introduced"`
			} `json:"filters"`
			Formats []string `json:"formats"`
		} `json:"attributes"`
		Type string `json:"type"`
	} `json:"data"`
}

type ExportResponse struct {
	Data struct {
		Attributes struct {
			Created string `json:"created"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

type ExportStatusResponse struct {
	Data struct {
		Attributes struct {
			Created string   `json:"created"`
			Formats []string `json:"formats"`
			Status  string   `json:"status,omitempty"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

type ExportResult struct {
	URL      string `json:"url"`
	FileSize int    `json:"file_size"`
	RowCount int    `json:"row_count"`
}

type ExportDownloadResponse struct {
	Data struct {
		Attributes struct {
			Finished            string   `json:"finished"`
			Formats             []string `json:"formats"`
			IntroducedDateRange struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"introduced_date_range"`
			Results  []ExportResult `json:"results"`
			RowCount int            `json:"row_count"`
			Status   string         `json:"status"`
		} `json:"attributes"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

type CSVRecord map[string]string

type Report struct {
	Date     string       `json:"date"`
	OrgID    string       `json:"org_id,omitempty"`
	FromDate string       `json:"from_date,omitempty"`
	ToDate   string       `json:"to_date,omitempty"`
	Report   ReportDetail `json:"report"`
}

type ReportDetail struct {
	Critical ReportStats `json:"critical"`
	High     ReportStats `json:"high"`
	Medium   ReportStats `json:"medium"`
	Low      ReportStats `json:"low"`
}

type ReportStats struct {
	Total    int `json:"total"`
	Open     int `json:"open"`
	Ignored  int `json:"ignored"`
	Resolved int `json:"resolved"`
}

type Config struct {
	SnykAPIBaseURL string
	SnykOrgID      string
	SnykAPIKey     string
	APIVersion     string
	ExportID       string

	FromDate string
	ToDate   string
}

func main() {
	config := getConfig()

	fmt.Println("Creating export...")
	exportID, err := createExport(config)
	config.ExportID = exportID
	if err != nil {
		log.Fatalf("Failed to create export: %v", err)
	}
	fmt.Printf("Export created with ID: %s\n", exportID)
	time.Sleep(5 * time.Second) // delay due to job creation

	fmt.Println("Waiting for export to be ready...")
	err = checkExportStatus(config)
	if err != nil {
		log.Fatalf("Failed to check export status: %v", err)
	}
	fmt.Println("Export is ready!")

	fmt.Println("Downloading export metadata...")
	exportData, err := downloadExport(config)
	if err != nil {
		log.Fatalf("Failed to download export: %v", err)
	}

	fmt.Printf("Export contains %d CSV files with %d total rows\n",
		len(exportData.Data.Attributes.Results),
		exportData.Data.Attributes.RowCount)

	fmt.Println("Downloading and processing CSV files...")
	var allRecords []CSVRecord

	var result Report
	result.Report = ReportDetail{
		Critical: ReportStats{},
		High:     ReportStats{},
		Medium:   ReportStats{},
		Low:      ReportStats{},
	}
	result.Date = time.Now().Format("2006-01-02")
	result.OrgID = config.SnykOrgID
	result.FromDate = config.FromDate
	result.ToDate = config.ToDate

	for i, exportResult := range exportData.Data.Attributes.Results {
		fmt.Printf("Downloading CSV file %d/%d (rows: %d, size: %d bytes)...\n",
			i+1, len(exportData.Data.Attributes.Results), exportResult.RowCount, exportResult.FileSize)

		csvData, err := downloadCSVFile(exportResult.URL, fmt.Sprintf("csv_file_%d.csv", i+1))
		if err != nil {
			log.Printf("Warning: Failed to download CSV file %d: %v", i+1, err)
			continue
		}

		records, err := processCSV(csvData)
		if err != nil {
			log.Printf("Warning: Failed to process CSV file %d: %v", i+1, err)
			continue
		}

		for _, record := range records {
			severity := record["ISSUE_SEVERITY"]
			status := record["ISSUE_STATUS"]

			var severityProperty *ReportStats
			switch severity {
			case "Critical":
				severityProperty = &result.Report.Critical
			case "High":
				severityProperty = &result.Report.High
			case "Medium":
				severityProperty = &result.Report.Medium
			case "Low":
				severityProperty = &result.Report.Low
			}

			if severityProperty != nil {
				severityProperty.Total++

				switch status {
				case "Open":
					severityProperty.Open++
				case "Ignored":
					severityProperty.Ignored++
				case "Resolved":
					severityProperty.Resolved++
				}
			}

		}

		fmt.Printf("Processed %d records from CSV file %d\n", len(records), i+1)
	}

	saveReport(result)

	fmt.Printf("\nTotal records processed: %d\n", len(allRecords))
}

func getConfig() Config {
	var snykOrgID, snykAPIKey string

	if len(os.Args) > 1 && os.Args[1] != "" {
		snykOrgID = os.Args[1]
	} else {
		fmt.Fprintln(os.Stderr, "Error: Org ID is required")
		os.Exit(1)
	}

	var dateFrom, dateTo string
	if len(os.Args) > 2 && os.Args[2] != "" {
		dateFrom = os.Args[2]
		// Validate YYYY-MM-DD
		if _, err := time.Parse("2006-01-02", dateFrom); err != nil {
			fmt.Fprintf(os.Stderr, "Error: DateFrom ('%s') is not a valid YYYY-MM-DD date\n", dateFrom)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: DateFrom (YYYY-MM-DD) is required as argument 2")
		os.Exit(1)
	}
	if len(os.Args) > 3 && os.Args[3] != "" {
		dateTo = os.Args[3]
		if _, err := time.Parse("2006-01-02", dateTo); err != nil {
			fmt.Fprintf(os.Stderr, "Error: DateTo ('%s') is not a valid YYYY-MM-DD date\n", dateTo)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Error: DateTo (YYYY-MM-DD) is required as argument 3")
		os.Exit(1)
	}

	snykAPIKey = os.Getenv("SNYK_TOKEN")
	if snykAPIKey == "" {
		fmt.Fprintln(os.Stderr, "Error: SNYK_TOKEN environment variable is not set")
		os.Exit(1)
	}

	return Config{
		SnykAPIBaseURL: "https://api.snyk.io",
		SnykOrgID:      snykOrgID,
		SnykAPIKey:     snykAPIKey,
		APIVersion:     "2024-10-15",
		ExportID:       "",
		FromDate:       fmt.Sprintf("%sT00:00:00Z", dateFrom),
		ToDate:         fmt.Sprintf("%sT23:59:59Z", dateTo),
	}
}

func saveReport(result Report) {
	outFile := fmt.Sprintf("report_%s.json", result.Date)
	jsonData, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		log.Printf("Warning: Failed to marshal result as JSON: %v", err)
	} else {
		if err := os.WriteFile(outFile, jsonData, 0644); err != nil {
			log.Printf("Warning: Failed to write JSON report: %v", err)
		} else {
			fmt.Printf("Report saved to: %s\n", outFile)
		}
	}
}

func createExport(config Config) (string, error) {
	url := fmt.Sprintf("%s/rest/orgs/%s/export?version=%s", config.SnykAPIBaseURL, config.SnykOrgID, config.APIVersion)

	reqBody := ExportRequest{}
	reqBody.Data.Type = "resource"
	reqBody.Data.Attributes.Columns = []string{
		"PROJECT_NAME",
		"ISSUE_SEVERITY",
		"SCORE",
		"PROBLEM_TITLE",
		"FIRST_INTRODUCED",
		"PRODUCT_NAME",
		"ISSUE_URL",
		"ISSUE_STATUS",
	}
	reqBody.Data.Attributes.Dataset = "issues"
	reqBody.Data.Attributes.Filters.Introduced.From = config.FromDate
	reqBody.Data.Attributes.Filters.Introduced.To = config.ToDate
	reqBody.Data.Attributes.Formats = []string{"csv"}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("error marshaling request: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("authorization", fmt.Sprintf("token %s", config.SnykAPIKey))
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error making request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 202 {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("export creation failed with status %d: %s", res.StatusCode, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response: %w", err)
	}

	var exportResp ExportResponse
	err = json.Unmarshal(body, &exportResp)
	if err != nil {
		return "", fmt.Errorf("error unmarshaling response: %w", err)
	}

	if exportResp.Data.ID == "" {
		return "", fmt.Errorf("no export ID in response")
	}

	return exportResp.Data.ID, nil
}

func checkExportStatus(config Config) error {
	url := fmt.Sprintf("%s/rest/orgs/%s/jobs/export/%s?version=%s", config.SnykAPIBaseURL, config.SnykOrgID, config.ExportID, config.APIVersion)

	for {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("error creating request: %w", err)
		}

		req.Header.Add("authorization", fmt.Sprintf("token %s", config.SnykAPIKey))
		req.Header.Add("content-type", "application/json")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("error making request: %w", err)
		}

		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return fmt.Errorf("error reading response: %w", err)
		}

		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("status check failed with status %d: %s", res.StatusCode, string(body))
		}

		var statusResp ExportStatusResponse
		err = json.Unmarshal(body, &statusResp)
		if err != nil {
			return fmt.Errorf("error unmarshaling response: %w", err)
		}

		// If status is not present or empty, export is ready
		// If status is PENDING, wait and check again
		status := statusResp.Data.Attributes.Status
		if status == "" || status == "STARTED" || status == "FINISHED" {
			return nil
		}

		if status == "PENDING" {
			time.Sleep(1 * time.Second)
			continue
		}

		return fmt.Errorf("export status is %s", status)
	}
}

func downloadExport(config Config) (*ExportDownloadResponse, error) {
	url := fmt.Sprintf("%s/rest/orgs/%s/export/%s?version=%s", config.SnykAPIBaseURL, config.SnykOrgID, config.ExportID, config.APIVersion)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Add("authorization", fmt.Sprintf("token %s", config.SnykAPIKey))
	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("download failed with status %d: %s", res.StatusCode, string(body))
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	var downloadResp ExportDownloadResponse
	err = json.Unmarshal(body, &downloadResp)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	return &downloadResp, nil
}

func downloadCSVFile(url string, filename string) ([]byte, error) {
	res, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error downloading CSV: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CSV download failed with status %d", res.StatusCode)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CSV data: %w", err)
	}

	dir := "./csv"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if mkErr := os.MkdirAll(dir, 0755); mkErr != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, mkErr)
		}
	}

	filePath := filepath.Join(dir, filename)

	_ = os.WriteFile(filePath, data, 0644)

	return data, nil
}

func processCSV(csvData []byte) ([]CSVRecord, error) {
	reader := csv.NewReader(bytes.NewReader(csvData))

	headers, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("error reading CSV header: %w", err)
	}

	var records []CSVRecord

	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error reading CSV row: %w", err)
		}

		record := make(CSVRecord)
		for i, value := range row {
			if i < len(headers) {
				record[headers[i]] = value
			}
		}
		records = append(records, record)
	}

	return records, nil
}
