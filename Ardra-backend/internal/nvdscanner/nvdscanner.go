package nvdscanner

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

// CVE response structure
type CVE struct {
	ID          string `json:"cveId"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Reference   string `json:"reference"`
}

// ServiceScanSummary provides status for each service/version scanned
type ServiceScanSummary struct {
	Service      string `json:"service"`
	Version      string `json:"version,omitempty"`
	Status       string `json:"status"` // e.g., "SUCCESS", "FAILED", "NO_VULNERABILITIES_FOUND"
	ErrorMessage string `json:"error_message,omitempty"`
}

// NVDScanResponse is the full response structure for the /vuln-scan endpoint
type NVDScanResponse struct {
	Subdomain          string               `json:"subdomain"`
	ServiceScanResults []ServiceScanSummary `json:"service_scan_results"`
	Vulnerabilities    []CVE                `json:"vulnerabilities,omitempty"`
	OverallStatus      string               `json:"overall_status"`
	OverallError       string               `json:"overall_error,omitempty"`
}

// StartNVDScanner initializes the NVD scanner service
func StartNVDScanner(port string, db *sql.DB) {
	http.HandleFunc("/vuln-scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests allowed", http.StatusMethodNotAllowed)
			return
		}

		var reqBody struct {
			Subdomain string `json:"subdomain"`
			ApiKey    string `json:"api_key"`
		}

		var apiResponse NVDScanResponse
		apiResponse.OverallStatus = "FAILED"

		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			apiResponse.OverallError = fmt.Sprintf("Invalid JSON format: %v", err)
			json.NewEncoder(w).Encode(apiResponse)
			return
		}

		apiResponse.Subdomain = reqBody.Subdomain

		if reqBody.Subdomain == "" {
			http.Error(w, "Subdomain is required", http.StatusBadRequest)
			apiResponse.OverallError = "Subdomain is required"
			json.NewEncoder(w).Encode(apiResponse)
			return
		}
		if reqBody.ApiKey == "" {
			http.Error(w, "API key is required", http.StatusBadRequest)
			apiResponse.OverallError = "API key is required"
			json.NewEncoder(w).Encode(apiResponse)
			return
		}

		log.Printf("Starting vulnerability analysis for: %s", reqBody.Subdomain)

		var overallVulnerabilities []CVE
		var serviceScanSummaries []ServiceScanSummary

		serviceScanSummaries, overallVulnerabilities, err := ProcessVulnerabilities(db, reqBody.Subdomain, reqBody.ApiKey)
		if err != nil {
			apiResponse.OverallError = fmt.Sprintf("Vulnerability processing failed: %v", err)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(apiResponse)
			return
		}

		apiResponse.ServiceScanResults = serviceScanSummaries
		apiResponse.Vulnerabilities = overallVulnerabilities
		apiResponse.OverallStatus = "SUCCESS"
		if len(overallVulnerabilities) > 0 {
			apiResponse.OverallStatus = "VULNERABILITIES_FOUND"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(apiResponse)
	})

	log.Printf("Starting NVD Scanner service on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start NVD Scanner service: %v\n", err)
	}
}

// FetchVulnerabilities queries the NVD API for CVEs related to a given service and version
func FetchVulnerabilities(service, version, apiKey string) ([]CVE, error) {
	query := fmt.Sprintf("%s %s", service, version)
	query = strings.ReplaceAll(query, " ", "%20") // URL encoding

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&apiKey=%s", query, apiKey)

	client := &http.Client{Timeout: 15 * time.Second} // Increased timeout for reliability
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD API returned status: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading API response: %w", err)
	}

	var data struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSSV2 struct {
						BaseSeverity string `json:"baseSeverity"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("error parsing JSON response: %w", err)
	}

	var cves []CVE
	for _, vuln := range data.Vulnerabilities {
		description := "No description available"
		if len(vuln.CVE.Descriptions) > 0 {
			description = vuln.CVE.Descriptions[0].Value
		}

		severity := "Unknown"
		if vuln.CVE.Metrics.CVSSV2.BaseSeverity != "" {
			severity = vuln.CVE.Metrics.CVSSV2.BaseSeverity
		}

		reference := ""
		if len(vuln.CVE.References) > 0 {
			reference = vuln.CVE.References[0].URL
		}

		cves = append(cves, CVE{
			ID:          vuln.CVE.ID,
			Description: description,
			Severity:    severity,
			Reference:   reference,
		})
	}

	return cves, nil
}

// StoreVulnerabilities saves CVE results in the database
func StoreVulnerabilities(db *sql.DB, scanResultID int, service, version string, cves []CVE) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, cve := range cves {
		_, err := tx.Exec(`
            INSERT INTO vulnerabilities (scan_result_id, service, version, cve_id, description, severity, reference)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (scan_result_id, service, version, cve_id) DO NOTHING`,
			scanResultID, service, version, cve.ID, cve.Description, cve.Severity, cve.Reference)

		if err != nil {
			return fmt.Errorf("failed to insert CVE: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// ProcessVulnerabilities retrieves service information and runs CVE lookups
func ProcessVulnerabilities(db *sql.DB, subdomain string, apiKey string) ([]ServiceScanSummary, []CVE, error) {
	var scanResultID int
	err := db.QueryRow("SELECT id FROM scan_results WHERE subdomain = $1", subdomain).Scan(&scanResultID)
	if err != nil {
		return nil, nil, fmt.Errorf("scan result not found for %s: %w", subdomain, err)
	}

	rows, err := db.Query("SELECT service, version FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_result_id = $1)", scanResultID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch services for %s: %w", subdomain, err)
	}
	defer rows.Close()

	var serviceScanSummaries []ServiceScanSummary
	var overallVulnerabilities []CVE

	for rows.Next() {
		var service, version string
		if err := rows.Scan(&service, &version); err != nil {
			log.Printf("Error scanning service data: %v\n", err)
			continue
		}

		summary := ServiceScanSummary{Service: service, Version: version}

		// Check if the version is empty or a generic placeholder (like from port scanner)
		if version == "" || version == "Unknown" || service == "http" && version == "" {
			summary.Status = "SKIPPED_GENERIC_VERSION"
			summary.ErrorMessage = "NVD lookup skipped: Specific software version not detected by port scanner."
			serviceScanSummaries = append(serviceScanSummaries, summary)
			continue // Skip NVD API call for this entry
		}

		log.Printf("Fetching CVEs for: %s %s", service, version)
		cves, err := FetchVulnerabilities(service, version, apiKey)
		if err != nil {
			summary.Status = "FAILED"
			summary.ErrorMessage = err.Error()
			log.Printf("Error fetching CVEs for %s %s: %v\n", service, version, err)
		} else {
			if len(cves) > 0 {
				summary.Status = "SUCCESS"
				overallVulnerabilities = append(overallVulnerabilities, cves...)
				// Store vulnerabilities in the database
				if err := StoreVulnerabilities(db, scanResultID, service, version, cves); err != nil {
					log.Printf("Error storing vulnerabilities for %s %s: %v\n", service, version, err)
					summary.Status = "FAILED_DB_STORE"
					summary.ErrorMessage = fmt.Sprintf("Failed to store vulnerabilities: %v", err)
				}
			} else {
				summary.Status = "NO_VULNERABILITIES_FOUND"
			}
		}
		serviceScanSummaries = append(serviceScanSummaries, summary)
	}

	if err = rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("error iterating service rows: %w", err)
	}

	return serviceScanSummaries, overallVulnerabilities, nil
}
