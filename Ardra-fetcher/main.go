package main

import (
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	InitDB()
	defer DB.Close()

	r := gin.Default()
	r.GET("/api/subdomains", GetSubdomains)
	r.GET("/api/ports", GetPorts)
	r.GET("/api/status_results", GetStatusResults)
	r.GET("/api/subtakeovers", GetSubTakeovers)
	r.GET("/api/vulnerabilities", GetVulnerabilities)
	r.GET("/api/email_security_checks", GetEmailSecurityChecks)
	r.GET("/api/appchecker_output", GetAppCheckerOutput)
	r.GET("/api/dns_scans", GetDNSScans)
	r.GET("/api/discovered_keys", GetDiscoveredKeys)
	// Add more endpoints as needed

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}
