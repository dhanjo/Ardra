# Ardra - External Attack Surface Management (EASM) Platform

Ardra is a comprehensive External Attack Surface Management platform designed to discover, monitor, and analyze an organization's digital footprint. It provides automated security assessments across multiple domains including subdomain discovery, vulnerability scanning, DNS analysis, and application security testing.

## 🏗️ Architecture

The platform consists of three main microservices:

- **Ardra Backend** - Core security scanning engine with multiple specialized modules
- **Ardra Fetcher** - Data retrieval and management service  
- **Subhunt** - Specialized subdomain discovery service

## 🔍 Features

### Security Scanning Modules
- **DNS Analysis** - Comprehensive DNS record analysis, DNSSEC validation, zone transfer detection
- **Port Scanning** - Network port discovery and service identification using Nmap
- **Subdomain Discovery** - Multi-tool subdomain enumeration (subfinder, assetfinder, findomain, etc.)
- **Vulnerability Assessment** - CVE scanning and vulnerability correlation
- **Email Security** - SPF, DMARC, DKIM validation and MTA-STS analysis
- **Application Detection** - Technology stack identification using Wappalyzer
- **Subdomain Takeover** - Detection of vulnerable subdomains susceptible to takeover
- **API Key Discovery** - Automated discovery of exposed API keys and secrets
- **HTTP Status Monitoring** - Website availability and response code tracking

### Infrastructure
- PostgreSQL database for persistent storage
- Docker containerization for easy deployment
- Health check endpoints for monitoring
- RESTful API architecture

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### Installation

1. Clone the repository:
```bash
git clone [<repository-url>](https://github.com/dhanjo/Ardra)
cd Ardra
```

2. Start the services:
```bash
docker-compose up -d
```

3. Verify deployment:
```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

### Service Endpoints

- **Ardra Backend**: Multiple ports (8082-8090) for different scanning modules
- **Ardra Fetcher**: Port 8080
- **Subhunt**: Port 8001
- **PostgreSQL**: Port 5432

## 📊 Database Schema

The platform uses PostgreSQL with tables for:
- DNS scan results
- Port scan findings
- Vulnerability data
- Subdomain discoveries
- Email security assessments
- Application fingerprints
- HTTP status results

## 🛠️ Technology Stack

- **Backend**: Go (Gin framework)
- **Subdomain Discovery**: Python with multiple tools integration
- **Database**: PostgreSQL 13
- **Containerization**: Docker & Docker Compose
- **Security Tools**: Nmap, various OSINT tools

## 📝 Usage

After deployment, you can interact with the platform through its REST APIs. Each service provides specific endpoints for different types of security assessments.

## 🔒 Security

This platform is designed for defensive security purposes only. It helps organizations:
- Discover their external attack surface
- Identify potential security vulnerabilities
- Monitor subdomain proliferation
- Assess email security configurations
- Track technology stack changes

## 📄 License

[Add your license information here]

## 🤝 Contributing

[Add contribution guidelines here]
