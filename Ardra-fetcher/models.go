package main

import "time"

type Subdomain struct {
	ID           int       `json:"id"`
	DomainName   string    `json:"domain_name"`
	Subdomain    string    `json:"subdomain"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

type Port struct {
	ID       int    `json:"id"`
	HostID   int    `json:"host_id"`
	Protocol string `json:"protocol"`
	PortID   int    `json:"port_id"`
	State    string `json:"state"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Method   string `json:"method"`
}

type StatusResult struct {
	SLD        string `json:"sld"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
}

type SubTakeover struct {
	ID           int       `json:"id"`
	SLD          string    `json:"sld"`
	Subdomain    string    `json:"subdomain"`
	Vulnerable   bool      `json:"vulnerable"`
	Service      string    `json:"service"`
	CNAME        string    `json:"cname"`
	HTTPStatus   int       `json:"http_status"`
	ErrorMessage string    `json:"error_message"`
	ScannedAt    time.Time `json:"scanned_at"`
}

type Vulnerability struct {
	ID           int    `json:"id"`
	ScanResultID int    `json:"scan_result_id"`
	Service      string `json:"service"`
	Version      string `json:"version"`
	CVEID        string `json:"cve_id"`
	Description  string `json:"description"`
	Severity     string `json:"severity"`
	Reference    string `json:"reference"`
}

type EmailSecurityCheck struct {
	Domain          string    `json:"domain"`
	MXRecords       []string  `json:"mx_records"`
	SPFFound        bool      `json:"spf_found"`
	SPFRaw          string    `json:"spf_raw"`
	SPFPolicy       string    `json:"spf_policy"`
	SPFIncludes     []string  `json:"spf_includes"`
	SPFWarnings     []string  `json:"spf_warnings"`
	DMARCFound      bool      `json:"dmarc_found"`
	DMARCRaw        string    `json:"dmarc_raw"`
	DMARCPolicy     string    `json:"dmarc_policy"`
	AlignmentSPF    string    `json:"alignment_spf"`
	AlignmentDKIM   string    `json:"alignment_dkim"`
	RUA             string    `json:"rua"`
	RUF             string    `json:"ruf"`
	SubdomainPolicy string    `json:"subdomain_policy"`
	DKIMSelectors   string    `json:"dkim_selectors"`
	MTAStsFound     bool      `json:"mta_sts_found"`
	MTAStsRaw       string    `json:"mta_sts_raw"`
	TLSRptFound     bool      `json:"tls_rpt_found"`
	TLSRptRaw       string    `json:"tls_rpt_raw"`
	CheckedAt       time.Time `json:"checked_at"`
}

type AppCheckerOutput struct {
	ID           int       `json:"id"`
	SLD          string    `json:"sld"`
	Subdomain    string    `json:"subdomain"`
	URL          string    `json:"url"`
	Output       string    `json:"output"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

type DNSScan struct {
	ID                    int       `json:"id"`
	SLD                   string    `json:"sld"`
	Domain                string    `json:"domain"`
	ARecords              []string  `json:"a_records"`
	AAAARecords           []string  `json:"aaaa_records"`
	MXRecords             []string  `json:"mx_records"`
	NSRecords             []string  `json:"ns_records"`
	CNAMERecord           string    `json:"cname_record"`
	TXTRecords            []string  `json:"txt_records"`
	DNSSECEnabled         bool      `json:"dnssec_enabled"`
	WildcardDetected      bool      `json:"wildcard_detected"`
	ZoneTransferAllowed   bool      `json:"zone_transfer_allowed"`
	ReverseDNS            string    `json:"reverse_dns"`
	CDNProvider           string    `json:"cdn_provider"`
	OpenRecursiveResolver bool      `json:"open_recursive_resolver"`
	ThreatIntel           string    `json:"threat_intel"`
	LatencyMS             int64     `json:"latency_ms"`
	ScannedAt             time.Time `json:"scanned_at"`
}

type DiscoveredKey struct {
	ID           int       `json:"id"`
	SLD          string    `json:"sld"`
	Subdomain    string    `json:"subdomain"`
	URL          string    `json:"url"`
	APIKey       string    `json:"api_key"`
	Provider     string    `json:"provider"`
	Description  string    `json:"description"`
	DiscoveredAt time.Time `json:"discovered_at"`
}
