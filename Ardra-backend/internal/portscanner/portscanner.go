package portscanner

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"posturemanagement/internal/database"
	scanner "posturemanagement/internal/portscanner/Scanner"

	_ "github.com/lib/pq"
)

type NmapScan struct {
	Hosts map[string]NmapHost `json:"hosts"`
}

type NmapHost struct {
	State       string         `json:"state"`
	Address     string         `json:"address"`
	AddressType string         `json:"addressType"`
	Hostnames   []NmapHostname `json:"hostnames"`
	Ports       []NmapPort     `json:"ports"`
}

type NmapHostname struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type NmapPort struct {
	Protocol string   `json:"protocol"`
	ID       int      `json:"id"`
	State    string   `json:"state"`
	Service  string   `json:"service"`
	Version  string   `json:"version"`
	Method   string   `json:"method"`
	Scripts  []string `json:"scripts"`
}

// Scan request structure
type ScanRequest struct {
	Subdomain string `json:"subdomain"`
	ScanType  string `json:"scan_type,omitempty"`
}

// Scan response structure
type ScanResponse struct {
	Subdomain string   `json:"subdomain"`
	Results   NmapScan `json:"results"`
	Error     string   `json:"error,omitempty"`
}

// **Concurrency Control with Context Support**
var maxWorkers = 10
var semaphore = make(chan struct{}, maxWorkers)

// WorkerPool manages concurrent operations with proper cleanup
type WorkerPool struct {
	semaphore chan struct{}
	maxWorkers int
}

func NewWorkerPool(maxWorkers int) *WorkerPool {
	return &WorkerPool{
		semaphore: make(chan struct{}, maxWorkers),
		maxWorkers: maxWorkers,
	}
}

func (wp *WorkerPool) Acquire() {
	wp.semaphore <- struct{}{}
}

func (wp *WorkerPool) Release() {
	<-wp.semaphore
}

// **Start Port Scanner API**
func StartPortScanner(port string, db *sql.DB) {
	wp := NewWorkerPool(maxWorkers)
	
	http.HandleFunc("/port-scan", func(w http.ResponseWriter, r *http.Request) {
		// Add timeout context for the entire request
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests allowed", http.StatusMethodNotAllowed)
			return
		}

		var reqBody ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			http.Error(w, "Invalid JSON format", http.StatusBadRequest)
			return
		}

		if reqBody.Subdomain == "" {
			http.Error(w, "Subdomain is required", http.StatusBadRequest)
			return
		}

		// Validate subdomain format
		if len(reqBody.Subdomain) > 253 {
			http.Error(w, "Subdomain too long", http.StatusBadRequest)
			return
		}

		// Normalize scanType or set default
		scanType := strings.ToUpper(reqBody.ScanType)
		if scanType == "" {
			scanType = "DEFAULT"
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		var rawResult string
		var scanErr error

		wg.Add(1)
		wp.Acquire()

		// Running the scan with context support
		go func(subdomain string, sType string) {
			defer wg.Done()
			defer wp.Release()
			
			// Check if context is already cancelled
			select {
			case <-ctx.Done():
				mu.Lock()
				scanErr = ctx.Err()
				mu.Unlock()
				return
			default:
			}
			
			result, err := scanner.Scan(subdomain, sType)
			mu.Lock()
			rawResult = result
			scanErr = err
			mu.Unlock()
		}(reqBody.Subdomain, scanType)

		// Wait with context support
		done := make(chan struct{})
		go func() {
			wg.Wait()
			done <- struct{}{}
		}()

		select {
		case <-ctx.Done():
			http.Error(w, "Request timeout", http.StatusRequestTimeout)
			return
		case <-done:
			// Continue with normal processing
		}

		if scanErr != nil {
			http.Error(w, scanErr.Error(), http.StatusInternalServerError)
			return
		}

		var parsedScan NmapScan
		if err := json.Unmarshal([]byte(rawResult), &parsedScan); err != nil {
			log.Printf("Error parsing JSON from Nmap scanner: %v", err)
			log.Printf("Raw result that failed parsing: %s", rawResult)
			http.Error(w, "Failed to parse scan results", http.StatusInternalServerError)
			return
		}

		// Store scan results in the database
		if err := storeOrReplaceScanResults(db, reqBody.Subdomain, parsedScan); err != nil {
			log.Printf("Error storing scan result: %v\n", err)
			http.Error(w, "Failed to store scan result", http.StatusInternalServerError)
			return
		}

		response := ScanResponse{
			Subdomain: reqBody.Subdomain,
			Results:   parsedScan,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	log.Printf("Port Scanner running on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v\n", err)
	}
}

// **Database: Store Scan Results with improved error handling**
func storeOrReplaceScanResults(db *sql.DB, subdomain string, scan NmapScan) error {
	// Use context with timeout for database operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("transaction error: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			log.Printf("Error rolling back transaction: %v", err)
		}
	}()

	// **Insert/Update Scan Results**
	var existingID int
	err = tx.QueryRowContext(ctx, `
        INSERT INTO scan_results (subdomain) VALUES ($1)
        ON CONFLICT (subdomain) DO UPDATE SET scanned_at = CURRENT_TIMESTAMP
        RETURNING id`, subdomain).Scan(&existingID)
	if err != nil {
		return fmt.Errorf("insert/update error: %w", err)
	}

	// **Delete old related data with context**
	_, err = tx.ExecContext(ctx, `DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE scan_result_id = $1)`, existingID)
	if err != nil {
		return fmt.Errorf("error deleting old ports: %w", err)
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM hosts WHERE scan_result_id = $1`, existingID)
	if err != nil {
		return fmt.Errorf("error deleting old hosts: %w", err)
	}

	// **Insert new hosts with context**
	for address, host := range scan.Hosts {
		var hostID int
		err = tx.QueryRowContext(ctx, `
            INSERT INTO hosts (scan_result_id, address, state, address_type)
            VALUES ($1, $2, $3, $4) RETURNING id`, existingID, address, host.State, host.AddressType).Scan(&hostID)
		if err != nil {
			return fmt.Errorf("insert hosts error: %w", err)
		}

		// **Insert new ports with correct version handling and batch processing**
		if len(host.Ports) > 0 {
			// Prepare batch insert for ports
			batchSize := 100
			for i := 0; i < len(host.Ports); i += batchSize {
				end := i + batchSize
				if end > len(host.Ports) {
					end = len(host.Ports)
				}
				
				batch := host.Ports[i:end]
				for _, p := range batch {
					serviceVersion := p.Version
					if serviceVersion == "" {
						serviceVersion = "Unknown"
					}

					_, err := tx.ExecContext(ctx, `
                        INSERT INTO ports (host_id, protocol, port_id, state, service, version, method)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (host_id, port_id) DO UPDATE
                        SET state = EXCLUDED.state, service = EXCLUDED.service, version = EXCLUDED.version, method = EXCLUDED.method`,
						hostID, p.Protocol, p.ID, p.State, p.Service, serviceVersion, p.Method)
					if err != nil {
						return fmt.Errorf("failed to insert into ports: %w", err)
					}
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit error: %w", err)
	}
	return nil
}

// **ConnectToDB: Creates and Verifies a PostgreSQL DB Connection**
func ConnectToDB() (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		database.DbHost, database.DbPort, database.DbUser, database.DbPassword, database.DbName)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	log.Println("Successfully connected to the database")
	return db, nil
}
