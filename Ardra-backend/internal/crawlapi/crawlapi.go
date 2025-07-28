package crawlapi

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gocolly/colly/v2"

	_ "github.com/lib/pq"
)

var (
	db *sql.DB // Global database connection
)

// CrawlSession represents a single crawl session with isolated state
type CrawlSession struct {
	visited    map[string]bool
	uniqueKeys map[string]bool
	keyCount   int
	maxKeys    int
	mu         sync.RWMutex
}

type crawlRequest struct {
	URL               string `json:"url" binding:"required"`
	MaxDepth          int    `json:"max_depth,omitempty"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty"`
	MaxPages          int    `json:"max_pages,omitempty"`
	TimeoutSeconds    int    `json:"timeout_seconds,omitempty"`
}

// InitDB initializes the PostgreSQL connection and ensures the table exists.
func InitDB(databaseConnection *sql.DB) {
	db = databaseConnection // Assign the passed database connection to the package-level variable

	// Create table if not exists
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS discovered_keys (
		id SERIAL PRIMARY KEY,
		sld TEXT NOT NULL,
		subdomain TEXT NOT NULL,
		url TEXT NOT NULL,
		api_key TEXT NOT NULL UNIQUE,
		provider TEXT NOT NULL,
		description TEXT NOT NULL,
		discovered_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		UNIQUE (sld, subdomain, api_key)
	)`)
	if err != nil {
		log.Fatal("Failed to create discovered_keys table: ", err)
	}

	log.Println("Table 'discovered_keys' ensured.")
}

// StartCrawlAPI initializes the web service
func StartCrawlAPI(port string, databaseConnection *sql.DB) {
	// Ensure the database is initialized
	InitDB(databaseConnection)

	// Setup Gin router
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	// API Endpoint: Crawl a given URL
	router.POST("/api/v1/crawl", func(c *gin.Context) {
		var request crawlRequest
		if err := c.BindJSON(&request); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request"})
			return
		}

		// Set default values if not provided
		if request.MaxDepth == 0 {
			request.MaxDepth = 2 // Default crawl depth
		}
		if request.MaxPages == 0 {
			request.MaxPages = 1000 // Default max pages
		}
		if request.TimeoutSeconds == 0 {
			request.TimeoutSeconds = 60 // Default timeout in seconds
		}

		// Create a new session for each request to prevent memory leaks
		session := &CrawlSession{
			visited:    make(map[string]bool),
			uniqueKeys: make(map[string]bool),
			keyCount:   0,
			maxKeys:    10,
		}
		results, stoppedEarly := session.crawlAndDiscoverKeys(request.URL, request.MaxDepth, request.IncludeSubdomains, request.MaxPages, request.TimeoutSeconds)
		resp := gin.H{"results": results}
		if stoppedEarly {
			resp["warning"] = "Crawl stopped early due to timeout or max pages limit."
		}
		c.JSON(200, resp)
	})

	// Start the API server
	log.Printf("Crawl API service running on port %s\n", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatal("Failed to start Crawl API: ", err)
	}
}

// crawlAndDiscoverKeys performs web crawling and extracts API keys
func (s *CrawlSession) crawlAndDiscoverKeys(startURL string, maxDepth int, includeSubdomains bool, maxPages int, timeoutSeconds int) (map[string][]map[string]string, bool) {
	results := make(map[string][]map[string]string)
	stoppedEarly := false
	visitedPages := 0

	rootDomain := getDomain(startURL)

	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(maxDepth),
	)

	c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Delay:       2 * time.Second,
		RandomDelay: 1 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	c.OnRequest(func(r *colly.Request) {
		select {
		case <-ctx.Done():
			stoppedEarly = true
			r.Abort()
			return
		default:
			if visitedPages >= maxPages {
				stoppedEarly = true
				r.Abort()
				return
			}
			visitedPages++
		}
		if !includeSubdomains {
			if !strings.EqualFold(r.URL.Host, rootDomain) && !strings.EqualFold(strings.TrimPrefix(r.URL.Host, "www."), rootDomain) {
				fmt.Printf("Skipping non-root domain URL: %s\n", r.URL)
				r.Abort()
				return
			}
		} else {
			if !strings.HasSuffix(r.URL.Host, rootDomain) {
				fmt.Printf("Skipping out-of-domain URL: %s\n", r.URL)
				r.Abort()
				return
			}
		}
		r.Headers.Set("User-Agent", "Mozilla/5.0")
		fmt.Printf("Visiting: %s\n", r.URL.String())
	})

	c.OnHTML("html", func(e *colly.HTMLElement) {
		pageURL := e.Request.URL.String()

		s.mu.Lock()
		if s.visited[pageURL] || s.keyCount >= s.maxKeys {
			s.mu.Unlock()
			return
		}
		s.visited[pageURL] = true
		s.mu.Unlock()

		pageKeys := s.extractAPIKeys(e.Text, pageURL)

		s.mu.Lock()
		results[pageURL] = pageKeys
		s.keyCount += len(pageKeys)
		s.mu.Unlock()
	})

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Request.AbsoluteURL(e.Attr("href"))
		if link == "" {
			return
		}
		s.mu.RLock()
		isVisited := s.visited[link]
		s.mu.RUnlock()
		if !isVisited {
			c.Visit(link)
		}
	})

	c.OnError(func(r *colly.Response, err error) {
		log.Printf("Error visiting %s: %v", r.Request.URL, err)
	})

	done := make(chan struct{})
	go func() {
		c.Visit(startURL)
		c.Wait()
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		stoppedEarly = true
		// c.Stop() is not available in Colly; context will prevent new requests and abort ongoing ones.
		// Just return and let goroutines finish naturally.
	case <-done:
		// finished normally
	}

	return results, stoppedEarly
}

// extractAPIKeys searches for API keys and stores them in the database
func (s *CrawlSession) extractAPIKeys(content, pageURL string) []map[string]string {
	sld := getDomain(pageURL)
	subdomain := getSubdomain(pageURL)

	patterns := []struct {
		Pattern     string
		Provider    string
		Description string
	}{
		{`AKIA[0-9A-Z]{16}`, "AWS", "Amazon Web Services Access Key"},
		{`AIza[0-9A-Za-z-_]{35}`, "Google", "Google Cloud API Key"},
		{`sk_live_[0-9a-zA-Z]{24}`, "Stripe", "Stripe Secret Key"},
		{`ghp_[A-Za-z0-9_]{36}`, "GitHub", "GitHub Personal Access Token"},
	}

	var results []map[string]string
	for _, item := range patterns {
		re := regexp.MustCompile(item.Pattern)
		matches := re.FindAllString(content, -1)

		for _, match := range matches {
			if !s.uniqueKeys[match] {
				s.uniqueKeys[match] = true
				results = append(results, map[string]string{
					"key":         match,
					"provider":    item.Provider,
					"description": item.Description,
				})

				// Store in PostgreSQL
				storeAPIKey(sld, subdomain, pageURL, match, item.Provider, item.Description)
			}
		}
	}
	return results
}

// storeAPIKey saves the discovered API key into the PostgreSQL database
func storeAPIKey(sld, subdomain, url, key, provider, description string) {
	_, err := db.Exec(`
		INSERT INTO discovered_keys (sld, subdomain, url, api_key, provider, description)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (sld, subdomain, api_key) DO NOTHING
	`,
		sld, subdomain, url, key, provider, description)
	if err != nil {
		log.Printf("Failed to store API key: %v", err)
	}
}

// getDomain extracts the root domain (SLD+TLD) from a URL
// e.g. "www.acorns.com" -> "acorns.com"
func getDomain(rawURL string) string {
	u, _ := url.Parse(rawURL)
	host := strings.TrimPrefix(u.Hostname(), "www.")
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// getSubdomain extracts the subdomain from a URL
// e.g. "store.acorns.com" -> "store"
func getSubdomain(rawURL string) string {
	u, _ := url.Parse(rawURL)
	host := u.Hostname()
	return strings.TrimSuffix(host, "."+getDomain(rawURL))
}

// isMainPage checks if the URL is short enough to be considered a "main page"
func isMainPage(link string) bool {
	parts := strings.Split(link, "/")
	return len(parts) <= 4
}
