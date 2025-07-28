package dnschecker

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/miekg/dns"
)

var db *sql.DB

// InitDB initializes the PostgreSQL connection and creates the table if needed.
func InitDB(databaseConnection *sql.DB) {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	// Create the table if it doesn't exist. Using SLD + ID as composite primary key.
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS dns_scans (
    id SERIAL,
    sld TEXT NOT NULL,
    domain TEXT NOT NULL,
    
    -- DNS Records
    a_records TEXT[] NOT NULL,
    aaaa_records TEXT[] NOT NULL,
    mx_records TEXT[] NOT NULL,
    ns_records TEXT[] NOT NULL,
    cname_record TEXT,
    txt_records TEXT[] NOT NULL,

    -- Security Checks
    dnssec_enabled BOOLEAN NOT NULL,
    wildcard_detected BOOLEAN NOT NULL,
    zone_transfer_allowed BOOLEAN NOT NULL,
    reverse_dns TEXT,
    cdn_provider TEXT,
    open_recursive_resolver BOOLEAN NOT NULL,
    threat_intel JSONB NOT NULL,

    -- Timing
    latency_ms BIGINT NOT NULL,
    scanned_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (sld, id)
)
`)
	if err != nil {
		log.Fatal("Failed to create table dns_scans:", err)
	}

	log.Println("Ensured dns_scans table exists!")
}

// ------------------------------------------------------------------------
// 2) Data Structures
// ------------------------------------------------------------------------

// DNSSecurityResult holds standard DNS records plus security info.
type DNSSecurityResult struct {
	Domain                string            `json:"domain"`
	ARecords              []string          `json:"A,omitempty"`
	AAAARecords           []string          `json:"AAAA,omitempty"`
	MXRecords             []string          `json:"MX,omitempty"`
	NSRecords             []string          `json:"NS,omitempty"`
	CNAMERecord           string            `json:"CNAME,omitempty"`
	TXTRecords            []string          `json:"TXT,omitempty"`
	DNSSECEnabled         bool              `json:"dnssec_enabled"`
	WildcardDetected      bool              `json:"wildcard_detected"`
	ZoneTransferAllowed   bool              `json:"zone_transfer_allowed"`
	ReverseDNS            string            `json:"reverse_dns"`
	CDNProvider           string            `json:"cdn_provider"`
	OpenRecursiveResolver bool              `json:"open_recursive_resolver"`
	ThreatIntel           map[string]string `json:"threat_intel"`
	Latency               time.Duration     `json:"latency_ms"`
	// CNAMEChain is not fully implemented but kept for compatibility
	CNAMEChain []string `json:"cname_chain"`
}

// ------------------------------------------------------------------------
// 3) HTTP Server Entry Point
// ------------------------------------------------------------------------

// StartDNSChecker starts a single HTTP server on `port` and exposes only POST /dns.
// Example request body:
//
//	{ "domain": "sub.example.com" }
func StartDNSChecker(port string, databaseConnection *sql.DB) {
	InitDB(databaseConnection) // Initialize the database for this package
	http.HandleFunc("/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
			http.Error(w, "Invalid JSON payload (need {\"domain\": \"...\"})", http.StatusBadRequest)
			return
		}

		// Perform DNS + security checks
		results := scanDNSSecurity(req.Domain)

		// Insert the results into the dns_scans table
		if err := insertDNSResult(results); err != nil {
			log.Printf("Insert failed: %v\n", err)
		}

		// Return JSON response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(results)
	})

	log.Printf("DNS checker listening on port %s (POST /dns)\n", port)
	http.ListenAndServe(":"+port, nil)
}

// ------------------------------------------------------------------------
// 4) DNS / Security Scanning Logic
// ------------------------------------------------------------------------

// scanDNSSecurity gathers the DNS records and security checks into a DNSSecurityResult.
func scanDNSSecurity(domain string) DNSSecurityResult {
	start := time.Now()

	aRecs, aaaaRecs, mxRecs, nsRecs, cnameRec, txtRecs := gatherDNSRecords(domain)

	// Reverse DNS from first A or AAAA
	var reverse string
	if len(aRecs) > 0 {
		reverse = getReverseDNS(aRecs[0])
	} else if len(aaaaRecs) > 0 {
		reverse = getReverseDNS(aaaaRecs[0])
	}

	return DNSSecurityResult{
		Domain:                domain,
		ARecords:              aRecs,
		AAAARecords:           aaaaRecs,
		MXRecords:             mxRecs,
		NSRecords:             nsRecs,
		CNAMERecord:           cnameRec,
		TXTRecords:            txtRecs,
		DNSSECEnabled:         checkDNSSEC(domain),
		WildcardDetected:      strings.Contains(domain, "*"),
		ZoneTransferAllowed:   checkZoneTransfer(domain),
		ReverseDNS:            reverse,
		CDNProvider:           checkCDNProvider(domain),
		OpenRecursiveResolver: false, // stub
		ThreatIntel:           queryThreatIntel(domain),
		Latency:               time.Since(start),
		CNAMEChain:            []string{},
	}
}

// gatherDNSRecords fetches A, AAAA, MX, NS, CNAME, and TXT for a domain.
func gatherDNSRecords(domain string) ([]string, []string, []string, []string, string, []string) {
	var (
		aRecs, aaaaRecs, mxRecs, nsRecs, txtRecs []string
		cnameRec                                 string
	)

	// A + AAAA
	if ips, err := net.LookupIP(domain); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				aRecs = append(aRecs, ip.String())
			} else {
				aaaaRecs = append(aaaaRecs, ip.String())
			}
		}
	}

	// MX
	if mxs, err := net.LookupMX(domain); err == nil {
		for _, mx := range mxs {
			mxRecs = append(mxRecs, mx.Host)
		}
	}

	// NS
	if nss, err := net.LookupNS(domain); err == nil {
		for _, ns := range nss {
			nsRecs = append(nsRecs, ns.Host)
		}
	}

	// CNAME
	if c, err := net.LookupCNAME(domain); err == nil {
		// If c != domain, it's a real CNAME
		if !strings.EqualFold(c, domain) {
			cnameRec = c
		}
	}

	// TXT
	if txts, err := net.LookupTXT(domain); err == nil {
		txtRecs = append(txtRecs, txts...)
	}

	return aRecs, aaaaRecs, mxRecs, nsRecs, cnameRec, txtRecs
}

// checkDNSSEC verifies if DNSSEC is enabled for the domain.
func checkDNSSEC(domain string) bool {
	client := new(dns.Client)
	msg := new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)

	if r, _, err := client.Exchange(msg, "8.8.8.8:53"); err == nil && len(r.Answer) > 0 {
		return true
	}
	return false
}

// checkZoneTransfer attempts a DNS AXFR for each NS record.
func checkZoneTransfer(domain string) bool {
	nsRecords, _ := net.LookupNS(domain)
	for _, ns := range nsRecords {
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))
		t := new(dns.Transfer)

		addr := net.JoinHostPort(ns.Host, "53")
		ch, err := t.In(m, addr)
		if err == nil {
			for range ch {
				return true // Means we got data from zone transfer
			}
		}
	}
	return false
}

// getReverseDNS does a PTR lookup for the given IP.
func getReverseDNS(ip string) string {
	ptrs, _ := net.LookupAddr(ip)
	if len(ptrs) > 0 {
		return ptrs[0]
	}
	return ""
}

// checkCDNProvider: naive detection of known CDNs by IP prefix.
func checkCDNProvider(domain string) string {
	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		s := ip.String()
		// Very naive approach for Cloudflare or Akamai
		if strings.HasPrefix(s, "104.") || strings.HasPrefix(s, "172.") {
			return "Cloudflare"
		}
		if strings.HasPrefix(s, "151.") {
			return "Akamai"
		}
	}
	return "Unknown"
}

// queryThreatIntel is a placeholder for real threat intel lookups.
func queryThreatIntel(domain string) map[string]string {
	return map[string]string{
		"AbuseIPDB":  "No malicious activity detected",
		"VirusTotal": "Clean",
		"OpenPhish":  "No phishing reports",
		"ThreatFox":  "Not listed",
	}
}

// ------------------------------------------------------------------------
// 5) Database Insert Logic
// ------------------------------------------------------------------------

// insertDNSResult stores the DNS scan results in the "dns_scans" table.
// We'll parse out the SLD from the domain to fill the "sld" column.
func insertDNSResult(res DNSSecurityResult) error {
	if db == nil {
		return fmt.Errorf("database connection is not initialized")
	}

	sld := extractSLD(res.Domain)
	tiBytes, _ := json.Marshal(res.ThreatIntel) // threat_intel as JSONB

	stmt := `
INSERT INTO dns_scans (
    sld,
    domain,
    a_records,
    aaaa_records,
    mx_records,
    ns_records,
    cname_record,
    txt_records,
    dnssec_enabled,
    wildcard_detected,
    zone_transfer_allowed,
    reverse_dns,
    cdn_provider,
    open_recursive_resolver,
    threat_intel,
    latency_ms
) VALUES (
    $1, $2,
    $3, $4,
    $5, $6,
    $7, $8,
    $9, $10,
    $11, $12,
    $13, $14,
    $15, $16
)
RETURNING id
`

	_, err := db.Exec(stmt,
		sld,
		res.Domain,
		stringSliceToPGArray(res.ARecords),
		stringSliceToPGArray(res.AAAARecords),
		stringSliceToPGArray(res.MXRecords),
		stringSliceToPGArray(res.NSRecords),
		res.CNAMERecord,
		stringSliceToPGArray(res.TXTRecords),
		res.DNSSECEnabled,
		res.WildcardDetected,
		res.ZoneTransferAllowed,
		res.ReverseDNS,
		res.CDNProvider,
		res.OpenRecursiveResolver,
		tiBytes,                    // JSONB
		res.Latency.Milliseconds(), // store as BIGINT
	)
	if err != nil {
		return err
	}

	// If we wanted the generated id from "RETURNING id", we could do:
	// err = db.QueryRow(stmt, ...).Scan(&newID)

	log.Printf("Inserted DNS scan (sld=%s, domain=%s)", sld, res.Domain)
	return nil
}

// extractSLD tries to parse a second-level domain from "sub.example.com" -> "example.com".
// If there's only one label, the entire domain is the SLD fallback.
func extractSLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	// Last two segments, e.g. "example" + "com"
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func stringSliceToPGArray(ss []string) string {
	if len(ss) == 0 {
		return "{}"
	}
	escaped := make([]string, len(ss))
	for i, s := range ss {
		// Escape double quotes
		s = strings.ReplaceAll(s, `"`, `\"`)
		escaped[i] = `"` + s + `"`
	}
	return "{" + strings.Join(escaped, ",") + "}"
}
