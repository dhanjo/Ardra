package statuschecker

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

var db *sql.DB

// InitDB initializes the database connection and ensures the status_results table exists.
func InitDB(databaseConnection *sql.DB) {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	// Create table if it does not exist
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS status_results (
		id SERIAL PRIMARY KEY,
		sld TEXT NOT NULL,
		url TEXT NOT NULL UNIQUE,
		status_code INT NOT NULL,
		error TEXT,
		discovered_at TIMESTAMP DEFAULT NOW()
	)`)
	if err != nil {
		// In a real application, you might want more sophisticated error handling
		panic(fmt.Sprintf("Failed to create status_results table: %v", err))
	}

	fmt.Println("Table 'status_results' ensured.")
}

type StatusResult struct {
	SLD   string `json:"sld"`
	URL   string `json:"url"`
	Code  int    `json:"status_code"`
	Error string `json:"error,omitempty"`
}

func getSLD(fullURL string) string {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}

	hostname := parsedURL.Hostname()
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1] // Extract SLD
	}
	return hostname
}

func saveToDatabase(results []StatusResult) error {
	// Use the package-level db connection
	if db == nil {
		return fmt.Errorf("database connection not initialized in statuschecker package")
	}

	for _, result := range results {
		_, err := db.Exec(`INSERT INTO status_results (sld, url, status_code, error) 
			VALUES ($1, $2, $3, $4) 
			ON CONFLICT (sld, url) DO UPDATE 
			SET status_code = EXCLUDED.status_code, error = EXCLUDED.error`,
			result.SLD, result.URL, result.Code, result.Error)
		if err != nil {
			return fmt.Errorf("failed to insert or update data for %s: %w", result.URL, err)
		}
	}

	return nil
}

func getStatusCode(url string) StatusResult {
	resp, err := http.Get(url)
	result := StatusResult{URL: url, SLD: getSLD(url)}
	if err != nil {
		result.Error = "Error reaching the URL"
		return result
	}
	defer resp.Body.Close()
	result.Code = resp.StatusCode
	return result
}

func StartStatusChecker(port string, databaseConnection *sql.DB) {
	InitDB(databaseConnection) // Initialize the database for this package
	http.HandleFunc("/check-status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
			return
		}

		var urls []string
		if err := json.NewDecoder(r.Body).Decode(&urls); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		var wg sync.WaitGroup
		var mut sync.Mutex
		var results []StatusResult

		for _, url := range urls {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				result := getStatusCode(url)
				mut.Lock()
				results = append(results, result)
				mut.Unlock()
			}(url)
		}

		wg.Wait()

		if err := saveToDatabase(results); err != nil {
			http.Error(w, fmt.Sprintf("Failed to save results to database: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	http.ListenAndServe(":"+port, nil)
}
