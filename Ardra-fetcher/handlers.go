package main

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

func GetSubdomains(c *gin.Context) {
	domain := c.Query("domain") // Optional filter
	var rows pgx.Rows
	var err error

	if domain != "" {
		rows, err = DB.Query(context.Background(), "SELECT id, domain_name, subdomain, discovered_at FROM subdomains WHERE domain_name=$1", domain)
	} else {
		rows, err = DB.Query(context.Background(), "SELECT id, domain_name, subdomain, discovered_at FROM subdomains")
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []Subdomain
	for rows.Next() {
		var s Subdomain
		err := rows.Scan(&s.ID, &s.DomainName, &s.Subdomain, &s.DiscoveredAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, s)
	}
	c.JSON(http.StatusOK, results)
}

func GetPorts(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, host_id, protocol, port_id, state, service, version, method FROM ports")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []Port
	for rows.Next() {
		var p Port
		err := rows.Scan(&p.ID, &p.HostID, &p.Protocol, &p.PortID, &p.State, &p.Service, &p.Version, &p.Method)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, p)
	}
	c.JSON(http.StatusOK, results)
}

func GetStatusResults(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT sld, url, status_code, error FROM status_results")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []StatusResult
	for rows.Next() {
		var s StatusResult
		err := rows.Scan(&s.SLD, &s.URL, &s.StatusCode, &s.Error)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, s)
	}
	c.JSON(http.StatusOK, results)
}

func GetSubTakeovers(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, sld, subdomain, vulnerable, service, cname, http_status, error_message, scanned_at FROM subtakeoverscan")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []SubTakeover
	for rows.Next() {
		var s SubTakeover
		err := rows.Scan(&s.ID, &s.SLD, &s.Subdomain, &s.Vulnerable, &s.Service, &s.CNAME, &s.HTTPStatus, &s.ErrorMessage, &s.ScannedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, s)
	}
	c.JSON(http.StatusOK, results)
}

func GetVulnerabilities(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, scan_result_id, service, version, cve_id, description, severity, reference FROM vulnerabilities")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		err := rows.Scan(&v.ID, &v.ScanResultID, &v.Service, &v.Version, &v.CVEID, &v.Description, &v.Severity, &v.Reference)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, v)
	}
	c.JSON(http.StatusOK, results)
}

func GetEmailSecurityChecks(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT domain, mx_records, spf_found, spf_raw, spf_policy, spf_includes, spf_warnings, dmarc_found, dmarc_raw, dmarc_policy, alignment_spf, alignment_dkim, rua, ruf, subdomain_policy, dkim_selectors, mta_sts_found, mta_sts_raw, tls_rpt_found, tls_rpt_raw, checked_at FROM email_security_checks")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []EmailSecurityCheck
	for rows.Next() {
		var e EmailSecurityCheck
		err := rows.Scan(&e.Domain, &e.MXRecords, &e.SPFFound, &e.SPFRaw, &e.SPFPolicy, &e.SPFIncludes, &e.SPFWarnings, &e.DMARCFound, &e.DMARCRaw, &e.DMARCPolicy, &e.AlignmentSPF, &e.AlignmentDKIM, &e.RUA, &e.RUF, &e.SubdomainPolicy, &e.DKIMSelectors, &e.MTAStsFound, &e.MTAStsRaw, &e.TLSRptFound, &e.TLSRptRaw, &e.CheckedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, e)
	}
	c.JSON(http.StatusOK, results)
}

func GetAppCheckerOutput(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, sld, subdomain, url, output, discovered_at FROM appchecker_output")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []AppCheckerOutput
	for rows.Next() {
		var a AppCheckerOutput
		err := rows.Scan(&a.ID, &a.SLD, &a.Subdomain, &a.URL, &a.Output, &a.DiscoveredAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, a)
	}
	c.JSON(http.StatusOK, results)
}

func GetDNSScans(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, sld, domain, a_records, aaaa_records, mx_records, ns_records, cname_record, txt_records, dnssec_enabled, wildcard_detected, zone_transfer_allowed, reverse_dns, cdn_provider, open_recursive_resolver, threat_intel, latency_ms, scanned_at FROM dns_scans")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []DNSScan
	for rows.Next() {
		var d DNSScan
		err := rows.Scan(&d.ID, &d.SLD, &d.Domain, &d.ARecords, &d.AAAARecords, &d.MXRecords, &d.NSRecords, &d.CNAMERecord, &d.TXTRecords, &d.DNSSECEnabled, &d.WildcardDetected, &d.ZoneTransferAllowed, &d.ReverseDNS, &d.CDNProvider, &d.OpenRecursiveResolver, &d.ThreatIntel, &d.LatencyMS, &d.ScannedAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, d)
	}
	c.JSON(http.StatusOK, results)
}

func GetDiscoveredKeys(c *gin.Context) {
	rows, err := DB.Query(context.Background(), "SELECT id, sld, subdomain, url, api_key, provider, description, discovered_at FROM discovered_keys")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var results []DiscoveredKey
	for rows.Next() {
		var d DiscoveredKey
		err := rows.Scan(&d.ID, &d.SLD, &d.Subdomain, &d.URL, &d.APIKey, &d.Provider, &d.Description, &d.DiscoveredAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		results = append(results, d)
	}
	c.JSON(http.StatusOK, results)
}
