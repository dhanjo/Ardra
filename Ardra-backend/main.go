package main

import (
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"posturemanagement/internal/appchecker"
	"posturemanagement/internal/crawlapi"
	"posturemanagement/internal/database"
	"posturemanagement/internal/dnschecker"
	"posturemanagement/internal/emailchecker"
	"posturemanagement/internal/health"
	"posturemanagement/internal/nvdscanner"
	"posturemanagement/internal/portscanner"
	"posturemanagement/internal/statuschecker"
	"posturemanagement/internal/subtakeover"
)

func startServiceWithRetry(name string, startFn interface{}, port string, db *sql.DB) {
	maxRetries := 3
	retryDelay := time.Second * 5

	for attempt := 1; attempt <= maxRetries; attempt++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Service %s crashed on attempt %d: %v\n", name, attempt, r)
					if attempt < maxRetries {
						log.Printf("Retrying %s service in %v...\n", name, retryDelay)
						time.Sleep(retryDelay)
					} else {
						log.Printf("Service %s failed after %d attempts, giving up\n", name, maxRetries)
					}
				}
			}()
			
			log.Printf("Starting %s service on port %s (attempt %d)\n", name, port, attempt)

			// Handle functions with or without database dependencies.
			switch start := startFn.(type) {
			case func(string, *sql.DB):
				start(port, db)
			case func(string):
				start(port)
			default:
				log.Printf("Invalid start function for %s\n", name)
				return
			}
		}()
		
		// If we get here without panic, the service started successfully
		log.Printf("Service %s started successfully\n", name)
		return
	}
}

func main() {
	fmt.Println("Starting security posture management services...")

	// Connect to the database centrally
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Failed to connect to database: %v\n", err)
	}
	defer db.Close()

	var wg sync.WaitGroup
	wg.Add(9) // Adjusted to 9 services (including health check)

	go func() {
		defer wg.Done()
		dnschecker.InitDB(db) // Initialize DB for DNS Checker
		startServiceWithRetry("DNS Checker", dnschecker.StartDNSChecker, "8089", db)
	}()
	go func() {
		defer wg.Done()
		emailchecker.InitDB(db) // Initialize DB for Email Checker
		startServiceWithRetry("Email Checker", emailchecker.StartEmailChecker, "8082", db)
	}()
	go func() {
		defer wg.Done()
		appchecker.InitDB(db) // Initialize DB for App Checker
		startServiceWithRetry("App Checker", appchecker.StartAppChecker, "8083", db)
	}()
	go func() {
		defer wg.Done()
		// portscanner.ConnectToDB() is removed as connection is central
		startServiceWithRetry("Port Scanner", portscanner.StartPortScanner, "8084", db)
	}()
	go func() {
		defer wg.Done()
		// statuschecker.InitDB() needs to be added/refactored for table creation
		startServiceWithRetry("Status Checker", statuschecker.StartStatusChecker, "8085", db)
	}()
	go func() {
		defer wg.Done()
		crawlapi.InitDB(db) // Initialize DB for Crawl API
		startServiceWithRetry("Crawl API", crawlapi.StartCrawlAPI, "8086", db)
	}()
	go func() {
		defer wg.Done()
		subtakeover.InitDB(db) // Initialize DB for SubTakeOver
		startServiceWithRetry("SubTakeOver", subtakeover.StartSubTakeOver, "8087", db)
	}()
	go func() {
		defer wg.Done()
		// NVD Scanner's StartNVDScanner already accepts db, so no separate InitDB call here for connection
		startServiceWithRetry("NVD Scanner", nvdscanner.StartNVDScanner, "8088", db)
	}()
	go func() {
		defer wg.Done()
		startServiceWithRetry("Health Check", health.StartHealthCheck, "8090", db)
	}()

	fmt.Println("All services started. Press Ctrl+C to stop.")
	wg.Wait()
}
