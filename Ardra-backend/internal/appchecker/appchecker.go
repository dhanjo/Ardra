package appchecker

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	_ "github.com/lib/pq"
	wappalyzergo "github.com/projectdiscovery/wappalyzergo"
)

var db *sql.DB

// InitDB initializes the PostgreSQL connection and ensures the table exists.
func InitDB(databaseConnection *sql.DB) {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	// Create table if it does not exist
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS appchecker_output (
		id SERIAL PRIMARY KEY,
		sld TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		url TEXT NOT NULL,
		output JSONB NOT NULL,
		discovered_at TIMESTAMP DEFAULT NOW(),
		UNIQUE (sld, subdomain)
	)`)
	if err != nil {
		log.Fatal("Failed to create appchecker_output table: ", err)
	}

	log.Println("Table 'appchecker_output' ensured.")
}

// TLSInfo holds TLS and certificate details.
type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	CertIssuer  string `json:"cert_issuer,omitempty"`
	CertSubject string `json:"cert_subject,omitempty"`
}

// AppFingerprint encapsulates HTTP response details, TLS info, and detected technologies.
type AppFingerprint struct {
	URL          string                 `json:"url"`
	Status       int                    `json:"status"`
	Server       string                 `json:"server"`
	ContentType  string                 `json:"content_type,omitempty"`
	ResponseTime time.Duration          `json:"response_time"`
	TLS          *TLSInfo               `json:"tls,omitempty"`
	Technologies map[string]interface{} `json:"technologies,omitempty"`
}

// getTLSInfo extracts TLS details from the connection state.
func getTLSInfo(state *tls.ConnectionState) *TLSInfo {
	if state == nil {
		return nil
	}
	tlsInfo := &TLSInfo{}
	switch state.Version {
	case tls.VersionTLS10:
		tlsInfo.Version = "TLS 1.0"
	case tls.VersionTLS11:
		tlsInfo.Version = "TLS 1.1"
	case tls.VersionTLS12:
		tlsInfo.Version = "TLS 1.2"
	case tls.VersionTLS13:
		tlsInfo.Version = "TLS 1.3"
	default:
		tlsInfo.Version = "Unknown"
	}
	tlsInfo.CipherSuite = fmt.Sprintf("0x%x", state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		tlsInfo.CertIssuer = cert.Issuer.CommonName
		tlsInfo.CertSubject = cert.Subject.CommonName
	}
	return tlsInfo
}

// FingerprintApplication performs a scan on the provided domain.
func FingerprintApplication(domain string) AppFingerprint {
	url := domain
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		url = "https://" + domain
	}
	start := time.Now()

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Avoid certificate verification
		},
	}
	client := http.Client{
		Timeout:   15 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return AppFingerprint{URL: url, Server: "Invalid URL", ResponseTime: time.Since(start)}
	}
	req.Header.Set("User-Agent", "AppChecker/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return AppFingerprint{URL: url, Server: "Unreachable", ResponseTime: time.Since(start)}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		bodyBytes = []byte{}
	}

	var tlsInfo *TLSInfo
	if resp.TLS != nil {
		tlsInfo = getTLSInfo(resp.TLS)
	}

	// Run Wappalyzer for technology detection
	wappalyzerClient, err := wappalyzergo.New()
	var detectedTechs map[string]interface{}
	if err == nil {
		rawFingerprints := wappalyzerClient.Fingerprint(resp.Header, bodyBytes)
		detectedTechs = make(map[string]interface{})
		for tech := range rawFingerprints {
			detectedTechs[tech] = struct{}{}
		}
	}

	return AppFingerprint{
		URL:          url,
		Status:       resp.StatusCode,
		Server:       resp.Header.Get("Server"),
		ContentType:  resp.Header.Get("Content-Type"),
		ResponseTime: time.Since(start),
		TLS:          tlsInfo,
		Technologies: detectedTechs,
	}
}

// ToJSON converts the fingerprint to a JSON string.
func (fp *AppFingerprint) ToJSON() (string, error) {
	out, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// extractSLD extracts the second-level domain (SLD) from the full domain.
func extractSLD(domain string) (string, string) {
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimSuffix(domain, "/")
	domain = strings.Split(domain, ":")[0]
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain, domain
	}
	sld := parts[len(parts)-2] + "." + parts[len(parts)-1]
	return sld, domain
}

// storeFingerprint inserts the scan result into the database.
func storeFingerprint(sld, subdomain, url, result string) error {
	query := `
		INSERT INTO appchecker_output (sld, subdomain, url, output, discovered_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (sld, subdomain)
		DO UPDATE SET url = EXCLUDED.url, output = EXCLUDED.output, discovered_at = CURRENT_TIMESTAMP;
	`
	_, err := db.Exec(query, sld, subdomain, url, result)
	if err != nil {
		return err
	}
	log.Printf("Stored fingerprint for subdomain: %s under SLD: %s\n", subdomain, sld)
	return nil
}

// StartAppChecker runs the HTTP server.
func StartAppChecker(port string, databaseConnection *sql.DB) {
	InitDB(databaseConnection) // Initialize the database for this package
	http.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Domain string `json:"domain"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)

		fp := FingerprintApplication(payload.Domain)
		jsonStr, _ := fp.ToJSON()
		sld, subdomain := extractSLD(payload.Domain)
		_ = storeFingerprint(sld, subdomain, fp.URL, jsonStr)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fp)
	})
	log.Printf("AppChecker service running on port %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
