package health

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// HealthStatus represents the health status of a service
type HealthStatus struct {
	Service   string `json:"service"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message,omitempty"`
}

// SystemHealth represents overall system health
type SystemHealth struct {
	Status   string          `json:"status"`
	Services []HealthStatus  `json:"services"`
	Uptime   string         `json:"uptime"`
}

var startTime = time.Now()

// StartHealthCheck starts the health check endpoint
func StartHealthCheck(port string, db *sql.DB) {
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		health := SystemHealth{
			Status: "healthy",
			Uptime: time.Since(startTime).String(),
			Services: []HealthStatus{},
		}

		// Check database connection
		dbStatus := HealthStatus{
			Service:   "database",
			Timestamp: time.Now().Format(time.RFC3339),
		}
		
		if err := db.Ping(); err != nil {
			dbStatus.Status = "unhealthy"
			dbStatus.Message = err.Error()
			health.Status = "degraded"
		} else {
			dbStatus.Status = "healthy"
		}
		
		health.Services = append(health.Services, dbStatus)

		// Add more service checks as needed
		services := []string{"dns-checker", "port-scanner", "crawl-api", "email-checker", "app-checker", "status-checker", "subtakeover", "nvd-scanner"}
		for _, service := range services {
			serviceStatus := HealthStatus{
				Service:   service,
				Status:    "running",
				Timestamp: time.Now().Format(time.RFC3339),
			}
			health.Services = append(health.Services, serviceStatus)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(health)
	})

	log.Printf("Health check endpoint running on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start health check server: %v\n", err)
	}
}