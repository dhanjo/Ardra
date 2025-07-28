package emailchecker

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

// --- [Struct Definitions] ---

// SPFInfo holds parsed SPF details
type SPFInfo struct {
	Found    bool     `json:"found"`
	Raw      string   `json:"raw,omitempty"`
	Policy   string   `json:"policy,omitempty"`   // e.g. "-all", "~all", "+all", "?all"
	Includes []string `json:"includes,omitempty"` // includes from the SPF record
	Warnings []string `json:"warnings,omitempty"` // e.g. multiple SPF records, invalid syntax
}

// DMARCInfo holds parsed DMARC details
type DMARCInfo struct {
	Found           bool   `json:"found"`
	Raw             string `json:"raw,omitempty"`
	Policy          string `json:"policy,omitempty"`         // p=none, p=quarantine, p=reject
	AlignmentSPF    string `json:"alignment_spf,omitempty"`  // aspf=r or aspf=s
	AlignmentDKIM   string `json:"alignment_dkim,omitempty"` // adkim=r or adkim=s
	Rua             string `json:"rua,omitempty"`
	Ruf             string `json:"ruf,omitempty"`
	SubdomainPolicy string `json:"subdomain_policy,omitempty"` // sp=none, sp=quarantine, sp=reject
}

// DKIMSelector holds info about a single DKIM selector
type DKIMSelector struct {
	Selector  string `json:"selector"`
	Found     bool   `json:"found"`
	RawRecord string `json:"raw_record,omitempty"`
}

// DKIMInfo holds all DKIM findings
type DKIMInfo struct {
	Selectors []DKIMSelector `json:"selectors"`
}

// MTASTSInfo holds MTA-STS record info
type MTASTSInfo struct {
	Found bool   `json:"found"`
	Raw   string `json:"raw,omitempty"` // e.g. "v=STSv1; id=2021012801"
}

// TLSRPTInfo holds TLS-RPT record info
type TLSRPTInfo struct {
	Found bool   `json:"found"`
	Raw   string `json:"raw,omitempty"` // e.g. "v=TLSRPTv1; rua=mailto:reports@example.com"
}

// EmailSecurityResult is the main response structure
type EmailSecurityResult struct {
	Domain  string     `json:"domain"`
	MX      []string   `json:"mx_records,omitempty"`
	SPF     SPFInfo    `json:"spf"`
	DMARC   DMARCInfo  `json:"dmarc"`
	DKIM    DKIMInfo   `json:"dkim"`
	MTASTS  MTASTSInfo `json:"mta_sts"`
	TLSRPT  TLSRPTInfo `json:"tls_rpt"`
	Checked time.Time  `json:"checked_at"`
}

// EmailRequest defines the expected structure of the POST request body
type EmailRequest struct {
	Domain        string   `json:"domain"`
	DKIMSelectors []string `json:"dkim_selectors,omitempty"`
}

// --- [Database Functions] ---

var db *sql.DB

// InitDB initializes the database connection and ensures tables exist.
func InitDB(databaseConnection *sql.DB) error {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	log.Println("Email Checker: Initializing database connection.")

	// Ensure the email_security_checks table exists with a PRIMARY KEY on domain
	if err := createEmailSecurityChecksTable(); err != nil {
		return fmt.Errorf("error ensuring email_security_checks table: %w", err)
	}

	return nil
}

// createEmailSecurityChecksTable creates the table if it does not exist.
func createEmailSecurityChecksTable() error {
	query := `
	CREATE TABLE IF NOT EXISTS email_security_checks (
		domain VARCHAR(255) PRIMARY KEY,
		mx_records TEXT[],
		spf_found BOOLEAN,
		spf_raw TEXT,
		spf_policy VARCHAR(255),
		spf_includes TEXT[],
		spf_warnings TEXT[],
		dmarc_found BOOLEAN,
		dmarc_raw TEXT,
		dmarc_policy VARCHAR(255),
		alignment_spf VARCHAR(10),
		alignment_dkim VARCHAR(10),
		rua TEXT,
		ruf TEXT,
		subdomain_policy VARCHAR(255),
		dkim_selectors JSONB,
		mta_sts_found BOOLEAN,
		mta_sts_raw TEXT,
		tls_rpt_found BOOLEAN,
		tls_rpt_raw TEXT,
		checked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("error creating email_security_checks table: %w", err)
	}
	log.Println("email_security_checks table ensured.")
	return nil
}

// insertEmailSecurityResult inserts the analysis result into the database
func insertEmailSecurityResult(result EmailSecurityResult) error {
	query := `
        INSERT INTO email_security_checks (
            domain,
            mx_records,
            spf_found,
            spf_raw,
            spf_policy,
            spf_includes,
            spf_warnings,
            dmarc_found,
            dmarc_raw,
            dmarc_policy,
            alignment_spf,
            alignment_dkim,
            rua,
            ruf,
            subdomain_policy,
            dkim_selectors,
            mta_sts_found,
            mta_sts_raw,
            tls_rpt_found,
            tls_rpt_raw,
            checked_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21
        )
        ON CONFLICT (domain) DO UPDATE SET
            mx_records = EXCLUDED.mx_records,
            spf_found = EXCLUDED.spf_found,
            spf_raw = EXCLUDED.spf_raw,
            spf_policy = EXCLUDED.spf_policy,
            spf_includes = EXCLUDED.spf_includes,
            spf_warnings = EXCLUDED.spf_warnings,
            dmarc_found = EXCLUDED.dmarc_found,
            dmarc_raw = EXCLUDED.dmarc_raw,
            dmarc_policy = EXCLUDED.dmarc_policy,
            alignment_spf = EXCLUDED.alignment_spf,
            alignment_dkim = EXCLUDED.alignment_dkim,
            rua = EXCLUDED.rua,
            ruf = EXCLUDED.ruf,
            subdomain_policy = EXCLUDED.subdomain_policy,
            dkim_selectors = EXCLUDED.dkim_selectors,
            mta_sts_found = EXCLUDED.mta_sts_found,
            mta_sts_raw = EXCLUDED.mta_sts_raw,
            tls_rpt_found = EXCLUDED.tls_rpt_found,
            tls_rpt_raw = EXCLUDED.tls_rpt_raw,
            checked_at = EXCLUDED.checked_at;
    `

	dkimSelectorsJSON, err := json.Marshal(result.DKIM.Selectors)
	if err != nil {
		return fmt.Errorf("error marshalling DKIM selectors: %v", err)
	}

	_, err = db.Exec(query,
		result.Domain,
		pq.Array(result.MX),
		result.SPF.Found,
		result.SPF.Raw,
		result.SPF.Policy,
		pq.Array(result.SPF.Includes),
		pq.Array(result.SPF.Warnings),
		result.DMARC.Found,
		result.DMARC.Raw,
		result.DMARC.Policy,
		result.DMARC.AlignmentSPF,
		result.DMARC.AlignmentDKIM,
		result.DMARC.Rua,
		result.DMARC.Ruf,
		result.DMARC.SubdomainPolicy,
		string(dkimSelectorsJSON),
		result.MTASTS.Found,
		result.MTASTS.Raw,
		result.TLSRPT.Found,
		result.TLSRPT.Raw,
		result.Checked,
	)
	if err != nil {
		return fmt.Errorf("error inserting into database: %v", err)
	}

	return nil
}

// --- [Core Functions] ---

// CheckEmailSecurity performs various email security checks
func CheckEmailSecurity(domain string, dkimSelectors ...string) EmailSecurityResult {
	// If the caller did not provide any selectors, try "default"
	if len(dkimSelectors) == 0 {
		dkimSelectors = []string{"default"}
	}

	result := EmailSecurityResult{
		Domain:  domain,
		Checked: time.Now(),
	}

	var wg sync.WaitGroup
	wg.Add(5) // For MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT

	go func() {
		defer wg.Done()
		result.MX = checkMX(domain)
	}()

	go func() {
		defer wg.Done()
		result.SPF = checkSPF(domain)
	}()

	go func() {
		defer wg.Done()
		result.DMARC = checkDMARC(domain)
	}()

	go func() {
		defer wg.Done()
		result.DKIM = checkDKIM(domain, dkimSelectors)
	}()
	go func() {
		defer wg.Done()
		result.MTASTS = checkMTASTS(domain)
	}()
	go func() {
		defer wg.Done()
		result.TLSRPT = checkTLSRPT(domain)
	}()

	wg.Wait()

	return result
}

// checkMX fetches MX records for a domain
func checkMX(domain string) []string {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Error looking up MX records for %s: %v", domain, err)
		return nil
	}

	var records []string
	for _, mx := range mxRecords {
		records = append(records, mx.Host)
	}
	return records
}

// checkSPF fetches and parses SPF record
func checkSPF(domain string) SPFInfo {
	spfInfo := SPFInfo{}
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Error looking up TXT records for SPF for %s: %v", domain, err)
		return spfInfo
	}

	var spfRecords []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecords = append(spfRecords, txt)
		}
	}

	if len(spfRecords) == 0 {
		return spfInfo // No SPF record found
	} else if len(spfRecords) > 1 {
		spfInfo.Warnings = append(spfInfo.Warnings, "Multiple SPF records found (RFC violation)")
	}

	spfInfo.Found = true
	spfInfo.Raw = spfRecords[0]
	parseSPFRecord(spfRecords[0], &spfInfo)
	return spfInfo
}

// parseSPFRecord parses the SPF record string to extract policy and includes.
func parseSPFRecord(record string, spf *SPFInfo) {
	parts := strings.Fields(record)
	for _, part := range parts {
		if strings.HasPrefix(part, "v=spf1") {
			continue
		} else if strings.HasPrefix(part, "include:") {
			spf.Includes = append(spf.Includes, strings.TrimPrefix(part, "include:"))
		} else if strings.HasSuffix(part, "all") {
			spf.Policy = part
		}
	}
}

// checkDMARC fetches and parses DMARC record
func checkDMARC(domain string) DMARCInfo {
	dmarcInfo := DMARCInfo{}
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		log.Printf("Error looking up TXT records for DMARC for %s: %v", dmarcDomain, err)
		return dmarcInfo
	}

	var dmarcRecords []string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcRecords = append(dmarcRecords, txt)
		}
	}

	if len(dmarcRecords) == 0 {
		return dmarcInfo
	} else if len(dmarcRecords) > 1 {
		log.Printf("Multiple DMARC records found for %s", domain)
		// Note: RFC discourages multiple DMARC records, but some implementations merge.
		// For simplicity, we'll use the first one found.
	}

	dmarcInfo.Found = true
	dmarcInfo.Raw = dmarcRecords[0]
	parseDMARCRecord(dmarcRecords[0], &dmarcInfo)
	return dmarcInfo
}

// parseDMARCRecord parses the DMARC record string.
func parseDMARCRecord(record string, dmarc *DMARCInfo) {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			dmarc.Policy = strings.TrimPrefix(part, "p=")
		} else if strings.HasPrefix(part, "aspf=") {
			dmarc.AlignmentSPF = strings.TrimPrefix(part, "aspf=")
		} else if strings.HasPrefix(part, "adkim=") {
			dmarc.AlignmentDKIM = strings.TrimPrefix(part, "adkim=")
		} else if strings.HasPrefix(part, "rua=") {
			dmarc.Rua = strings.TrimPrefix(part, "rua=")
		} else if strings.HasPrefix(part, "ruf=") {
			dmarc.Ruf = strings.TrimPrefix(part, "ruf=")
		} else if strings.HasPrefix(part, "sp=") {
			dmarc.SubdomainPolicy = strings.TrimPrefix(part, "sp=")
		}
	}
}

// checkDKIM fetches DKIM records for a domain and given selectors
func checkDKIM(domain string, selectors []string) DKIMInfo {
	dkimInfo := DKIMInfo{}
	for _, selector := range selectors {
		dkimRecord := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		txtRecords, err := net.LookupTXT(dkimRecord)
		selectorInfo := DKIMSelector{Selector: selector}
		if err != nil || len(txtRecords) == 0 {
			selectorInfo.Found = false
		} else {
			selectorInfo.Found = true
			selectorInfo.RawRecord = txtRecords[0]
		}
		dkimInfo.Selectors = append(dkimInfo.Selectors, selectorInfo)
	}
	return dkimInfo
}

// checkMTASTS fetches MTA-STS policy
func checkMTASTS(domain string) MTASTSInfo {
	stsInfo := MTASTSInfo{}
	// Check for _mta-sts TXT record
	txtRecords, err := net.LookupTXT("_mta-sts." + domain)
	if err != nil {
		return stsInfo
	}

	var stsRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=STSv1") {
			stsRecord = txt
			break
		}
	}

	if stsRecord == "" {
		return stsInfo
	}

	stsInfo.Found = true
	stsInfo.Raw = stsRecord

	return stsInfo
}

// checkTLSRPT fetches TLS-RPT record
func checkTLSRPT(domain string) TLSRPTInfo {
	rptInfo := TLSRPTInfo{}
	// Check for _smtp._tls TXT record
	txtRecords, err := net.LookupTXT("_smtp._tls." + domain)
	if err != nil {
		return rptInfo
	}

	var rptRecord string
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=TLSRPTv1") {
			rptRecord = txt
			break
		}
	}

	if rptRecord == "" {
		return rptInfo
	}

	rptInfo.Found = true
	rptInfo.Raw = rptRecord

	return rptInfo
}

// StartEmailChecker starts the Email Checker service
func StartEmailChecker(port string, databaseConnection *sql.DB) {
	// Initialize DB connection when the service starts
	if err := InitDB(databaseConnection); err != nil {
		log.Fatalf("Failed to initialize database for Email Checker: %v", err)
	}

	http.HandleFunc("/email-check", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST requests allowed", http.StatusMethodNotAllowed)
			return
		}

		var req EmailRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
			http.Error(w, "Invalid JSON payload (need {\"domain\": \"...\"})", http.StatusBadRequest)
			return
		}

		log.Printf("Starting email security scan for domain: %s", req.Domain)
		result := CheckEmailSecurity(req.Domain, req.DKIMSelectors...)

		// Store results in the database
		if err := insertEmailSecurityResult(result); err != nil {
			log.Printf("Error storing email security result for %s: %v", req.Domain, err)
			http.Error(w, "Failed to store scan results", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	log.Printf("Email Checker service running on port %s\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start Email Checker service: %v", err)
	}
}
