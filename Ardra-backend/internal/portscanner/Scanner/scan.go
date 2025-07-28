// scanner.go

package scanner

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/t94j0/nmap"
)

type CustomResult struct {
	Hosts map[string]nmap.Host `json:"Hosts"`
}

// Scan performs an Nmap scan based on the provided domain and scan type.
func Scan(domain string, scanType string) (string, error) {
	var wg sync.WaitGroup

	scan := nmap.Init()
	scan = scan.AddHosts(domain)

	// Set Nmap flags based on scanType
	switch scanType {
	case "SYN": // -sS: SYN scan (stealth scan)
		scan = scan.AddFlags("-sS", "--max-retries=2", "--min-rate=50", "--defeat-rst-ratelimit")
	case "VERSION": // -sV: Version detection
		scan = scan.AddFlags("-sS", "-sV", "--version-intensity", "9", "--max-retries=2", "--min-rate=50", "--defeat-rst-ratelimit")
	case "FULL": // -p-: Scan all ports, -sC: default scripts, -sV: version detection
		scan = scan.AddFlags("-p-", "-sS", "-sC", "-sV", "--version-intensity", "9", "--max-retries=2", "--min-rate=50", "--defeat-rst-ratelimit")
	case "DEFAULT": // Existing default behavior
		scan = scan.AddFlags("-sS", "-sV", "--version-intensity", "9", "--max-retries=2", "--min-rate=50", "--defeat-rst-ratelimit")
	default:
		// Fallback to default if an unknown scanType is provided
		log.Printf("Warning: Unknown scan type '%s' provided. Using DEFAULT scan type.", scanType)
		scan = scan.AddFlags("-sS", "-sV", "--version-intensity", "9", "--max-retries=2", "--min-rate=50", "--defeat-rst-ratelimit")
	}

	wg.Add(1)

	result, err := scan.Run()
	if err != nil {
		log.Printf("Nmap scan failed: %v", err)
		return "", fmt.Errorf("Nmap scan command failed: %w", err)
	}

	customResult := CustomResult{
		Hosts: result.Hosts,
	}

	jsonData, err := json.MarshalIndent(customResult, "", "  ")
	if err != nil {
		log.Printf("Error marshalling Nmap result to JSON: %v", err)
		return "", fmt.Errorf("failed to marshal Nmap result: %w", err)
	}

	log.Printf("Raw JSON output from Nmap scanner: %s", string(jsonData))

	if string(jsonData) == "{}" {
		return "", fmt.Errorf("No meaningful data for domain: %s", domain)
	}

	defer wg.Done()
	return string(jsonData), nil
}
