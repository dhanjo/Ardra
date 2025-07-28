-- ========================
-- DNS Scan
-- ========================
CREATE TABLE IF NOT EXISTS dns_scans (
    id SERIAL NOT NULL,
    sld TEXT NOT NULL,
    domain TEXT NOT NULL,
    a_records TEXT[] NOT NULL,
    aaaa_records TEXT[] NOT NULL,
    mx_records TEXT[] NOT NULL,
    ns_records TEXT[] NOT NULL,
    cname_record TEXT,
    txt_records TEXT[] NOT NULL,
    dnssec_enabled BOOLEAN NOT NULL,
    wildcard_detected BOOLEAN NOT NULL,
    zone_transfer_allowed BOOLEAN NOT NULL,
    reverse_dns TEXT,
    cdn_provider TEXT,
    open_recursive_resolver BOOLEAN NOT NULL,
    threat_intel JSONB NOT NULL,
    latency_ms BIGINT NOT NULL,
    scanned_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sld, id)
);

-- ========================
-- Status Code
-- ========================
CREATE TABLE status_results (
    sld TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INT,
    error TEXT,
    PRIMARY KEY (sld, url)
);

-- ========================
-- Email Security Checks
-- ========================
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

-- ========================
-- CrawlAPI
-- ========================
CREATE TABLE IF NOT EXISTS discovered_keys (
        id SERIAL PRIMARY KEY,
        sld TEXT NOT NULL,
        subdomain TEXT NOT NULL,
        url TEXT NOT NULL,
        api_key TEXT NOT NULL UNIQUE,
        provider TEXT NOT NULL,
        description TEXT NOT NULL,
        discovered_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (sld, subdomain, api_key)
    );

-- ========================
-- Portscan
-- ========================
CREATE TABLE scan_results (
    id SERIAL PRIMARY KEY,
    subdomain TEXT UNIQUE NOT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE hosts (
    id SERIAL PRIMARY KEY,
    scan_result_id INT REFERENCES scan_results(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    state TEXT NOT NULL,
    address_type TEXT NOT NULL
);

CREATE TABLE hostnames (
    id SERIAL PRIMARY KEY,
    host_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE ports (
    id SERIAL PRIMARY KEY,
    host_id INT REFERENCES hosts(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port_id INT NOT NULL,
    state TEXT NOT NULL,
    service TEXT NOT NULL,
    version TEXT DEFAULT 'Unknown',
    method TEXT NOT NULL,
    UNIQUE(host_id, port_id)
);

-- ========================
-- Subdomain Takeover
-- ========================
CREATE TABLE IF NOT EXISTS subtakeoverscan (
        id SERIAL PRIMARY KEY,
        sld TEXT NOT NULL,
        subdomain TEXT NOT NULL UNIQUE,
        vulnerable BOOLEAN NOT NULL,
        service TEXT,
        cname TEXT,
        http_status INT,
        error_message TEXT,
        scanned_at TIMESTAMP DEFAULT NOW()
);

-- ========================
-- Subdomain Finder
-- ========================
CREATE TABLE subdomains (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(255) NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT unique_domain_subdomain UNIQUE (domain_name, subdomain)
);

CREATE TABLE http_results (
    id SERIAL PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL,
    subdomain VARCHAR(255) NOT NULL,
    status_code INTEGER,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ========================
-- App Checker
-- ========================
CREATE TABLE IF NOT EXISTS appchecker_output (
    id SERIAL PRIMARY KEY,
    sld TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    url TEXT NOT NULL,
    output JSONB NOT NULL,
    discovered_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (sld, subdomain)
);


-- ========================
-- Vulnerabilities
-- ========================
CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_result_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    version TEXT,
    cve_id TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    reference TEXT
);

-- ========================
-- Subhunt Results
-- ========================
CREATE TABLE IF NOT EXISTS subhunt_results (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (domain, subdomain)
);