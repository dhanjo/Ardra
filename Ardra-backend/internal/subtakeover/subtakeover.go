package subtakeover

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type Service struct {
	Name  string
	Regex string
}

var services = []Service{
	{Name: "AWS/S3", Regex: `The specified bucket does not exist`},
	{Name: "GitHub", Regex: `There isn\\'t a GitHub Pages site here`},
	{Name: "Heroku", Regex: `no such app`},
	{Name: "Fastly", Regex: `Fastly error: unknown domain`},
	{Name: "Shopify", Regex: `Sorry, this shop is currently unavailable.`},
	{Name: "BitBucket", Regex: `Repository not found`},
	// Add more services as needed...
}

type RequestPayload struct {
	Subdomains []string `json:"subdomains"`
}

type SubdomainResult struct {
	Subdomain    string `json:"subdomain"`
	SLD          string `json:"sld"`
	Vulnerable   bool   `json:"vulnerable"`
	Service      string `json:"service,omitempty"`
	CNAME        string `json:"cname,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	ScannedAt    string `json:"scanned_at"`
}

type ResponsePayload struct {
	Results []SubdomainResult `json:"results"`
}

var db *sql.DB

// InitDB initializes the database connection and ensures the subtakeoverscan table exists.
func InitDB(databaseConnection *sql.DB) {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	// Create the table if it doesn't exist.
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS subtakeoverscan (
		id SERIAL PRIMARY KEY,
		sld TEXT NOT NULL,
		subdomain TEXT NOT NULL UNIQUE,
		vulnerable BOOLEAN NOT NULL,
		service TEXT,
		cname TEXT,
		http_status INT,
		error_message TEXT,
		scanned_at TIMESTAMP DEFAULT NOW()
	)`)
	if err != nil {
		log.Fatalf("Failed to create subtakeoverscan table: %v", err)
	}
	log.Println("Table 'subtakeoverscan' ensured in SubTakeOver.")
}

func checkSubdomain(url string, client *http.Client) SubdomainResult {
	result := SubdomainResult{
		Subdomain: url,
		SLD:       extractSLD(url),
		ScannedAt: time.Now().Format(time.RFC3339),
	}

	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}

	// Perform DNS lookup to fetch CNAME
	cname, err := net.LookupCNAME(strings.TrimPrefix(url, "http://"))
	if err == nil {
		result.CNAME = cname
	} else {
		result.ErrorMessage = fmt.Sprintf("DNS lookup failed: %v", err)
	}

	// Perform HTTP request
	resp, err := client.Get(url)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.HTTPStatus = resp.StatusCode

	// Safely read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to read response body: %v", err)
		return result
	}

	content := string(body)
	for _, service := range services {
		matched, _ := regexp.MatchString(service.Regex, content)
		if matched {
			result.Vulnerable = true
			result.Service = service.Name
			return result
		}
	}

	result.Vulnerable = false
	return result
}

func processSubdomains(subdomains []string) []SubdomainResult {
	var wg sync.WaitGroup
	results := make([]SubdomainResult, 0, len(subdomains))
	resultsChan := make(chan SubdomainResult, len(subdomains))
	client := &http.Client{}

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			resultsChan <- checkSubdomain(url, client)
		}(subdomain)
	}

	wg.Wait()
	close(resultsChan)

	for result := range resultsChan {
		results = append(results, result)
	}

	return results
}

func storeResultsInDB(results []SubdomainResult) error {
	// Use the package-level db connection
	if db == nil {
		return fmt.Errorf("database connection not initialized in subtakeover package")
	}

	query := `
		INSERT INTO subtakeoverscan (sld, subdomain, vulnerable, service, cname, http_status, error_message, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (subdomain) DO UPDATE SET
		vulnerable = EXCLUDED.vulnerable,
		service = EXCLUDED.service,
		cname = EXCLUDED.cname,
		http_status = EXCLUDED.http_status,
		error_message = EXCLUDED.error_message,
		scanned_at = EXCLUDED.scanned_at;
	`

	for _, result := range results {
		_, err := db.Exec(query, result.SLD, result.Subdomain, result.Vulnerable, result.Service, result.CNAME, result.HTTPStatus, result.ErrorMessage, result.ScannedAt)
		if err != nil {
			return fmt.Errorf("failed to insert result for %s: %v", result.Subdomain, err)
		}
	}

	return nil
}

func SubdomainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Safely read the entire request body first
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close() // Ensure body is closed

	var payload RequestPayload
	// Now decode from the byte slice
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		log.Printf("Error unmarshalling request payload: %v", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	results := processSubdomains(payload.Subdomains)

	// Store results in the database
	if err := storeResultsInDB(results); err != nil {
		http.Error(w, fmt.Sprintf("Failed to store results: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with results
	response := ResponsePayload{Results: results}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func StartSubTakeOver(port string, databaseConnection *sql.DB) {
	InitDB(databaseConnection) // Initialize the database and ensure table exists
	http.HandleFunc("/api/check", SubdomainHandler)
	fmt.Printf("SubTakeOver service is running on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Failed to start SubTakeOver service: %v\n", err)
	}
}

func extractSLD(subdomain string) string {
	parts := strings.Split(subdomain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return subdomain
}
