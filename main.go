package main

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"
	"golang.org/x/time/rate"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/hashicorp/golang-lru"
	"github.com/patrickmn/go-cache"
	"github.com/sony/gobreaker"
	"gopkg.in/yaml.v2"
)

const (
	bufSize     = 32 * 1024
	defaultPort = 8080
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)

	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of requests processed by the proxy",
		},
		[]string{"method", "status", "host"},
	)
	bytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_bytes_transferred",
			Help: "Total number of bytes transferred through the proxy",
		},
		[]string{"direction", "host"},
	)
	cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_cache_hits",
			Help: "Total number of cache hits",
		},
		[]string{"host"},
	)
	circuitBreakerStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "proxy_circuit_breaker_status",
			Help: "Status of the circuit breaker (0: Closed, 1: Half-Open, 2: Open)",
		},
		[]string{"host"},
	)
)

type Config struct {
	AllowedHosts []string `yaml:"allowed_hosts"`
	BlockedHosts []string `yaml:"blocked_hosts"`
	RateLimit    int      `yaml:"rate_limit"`
	Backends     []string `yaml:"backends"`
}

type Proxy struct {
	Transport      http.RoundTripper
	Credential     string
	Cache          *cache.Cache
	RateLimiter    *rate.Limiter
	Config         *Config
	CircuitBreaker *gobreaker.CircuitBreaker
	LoadBalancer   *lru.Cache
}

func NewProxy(configPath string) (*Proxy, error) {
	config, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}

	lbCache, _ := lru.New(100) // Cache for load balancing decisions

	cb := gobreaker.NewCircuitBreaker(gobreaker.Settings{
		Name:        "HTTP_PROXY",
		MaxRequests: 5,
		Interval:    10 * time.Second,
		Timeout:     30 * time.Second,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			return counts.Requests >= 3 && failureRatio >= 0.6
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			circuitBreakerStatus.WithLabelValues(name).Set(float64(to))
		},
	})

	return &Proxy{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
		},
		Cache:          cache.New(5*time.Minute, 10*time.Minute),
		RateLimiter:    rate.NewLimiter(rate.Every(time.Second), config.RateLimit),
		Config:         config,
		CircuitBreaker: cb,
		LoadBalancer:   lbCache,
	}, nil
}

func loadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (p *Proxy) proxyAuthCheck(r *http.Request) bool {
	if p.Credential == "" {
		return true
	}
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	return auth[len(prefix):] == p.Credential
}

func (p *Proxy) handleProxyAuth(w http.ResponseWriter, r *http.Request) bool {
	if p.proxyAuthCheck(r) {
		return true
	}
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"*\"")
	w.WriteHeader(http.StatusProxyAuthRequired)
	return false
}

func (p *Proxy) isAllowed(host string) bool {
	if len(p.Config.AllowedHosts) == 0 {
		return !p.isBlocked(host)
	}
	for _, allowed := range p.Config.AllowedHosts {
		if strings.HasSuffix(host, allowed) {
			return true
		}
	}
	return false
}

func (p *Proxy) isBlocked(host string) bool {
	for _, blocked := range p.Config.BlockedHosts {
		if strings.HasSuffix(host, blocked) {
			return true
		}
	}
	return false
}

func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if !p.isAllowed(r.Host) {
		http.Error(w, "Access to this host is not allowed", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(&wg, destConn, clientConn, r.Host)
	go transfer(&wg, clientConn, destConn, r.Host)
	wg.Wait()
}

func transfer(wg *sync.WaitGroup, destination io.WriteCloser, source io.ReadCloser, host string) {
	defer wg.Done()
	defer destination.Close()
	defer source.Close()
	n, _ := io.Copy(destination, source)
	bytesTransferred.WithLabelValues("out", host).Add(float64(n))
}

func (p *Proxy) modifyRequest(r *http.Request) {
	r.Header.Set("X-Forwarded-For", r.RemoteAddr)
	r.Header.Set("X-Proxied-By", "AdvancedGoProxy")
}

func (p *Proxy) modifyResponse(resp *http.Response) {
	resp.Header.Set("X-Proxy-Info", "Modified by AdvancedGoProxy")
}

func (p *Proxy) loadBalance(r *http.Request) {
	backends := p.Config.Backends
	if len(backends) == 0 {
		return
	}

	if host, ok := p.LoadBalancer.Get(r.Host); ok {
		index := (host.(int) + 1) % len(backends)
		p.LoadBalancer.Add(r.Host, index)
		r.URL.Host = backends[index]
	} else {
		p.LoadBalancer.Add(r.Host, 0)
		r.URL.Host = backends[0]
	}
}

func (p *Proxy) compressResponse(w http.ResponseWriter, r *http.Request, resp *http.Response) error {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return nil
	}

	gz := gzip.NewWriter(w)
	defer gz.Close()

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Del("Content-Length")

	_, err := io.Copy(gz, resp.Body)
	return err
}

func (p *Proxy) logRequest(r *http.Request, statusCode int, responseTime time.Duration) {
	logger.Printf(
		"%s - %s %s %s %d %v",
		r.RemoteAddr,
		r.Method,
		r.URL.Path,
		r.Proto,
		statusCode,
		responseTime,
	)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	if !p.handleProxyAuth(w, r) {
		return
	}

	if !p.isAllowed(r.Host) {
		http.Error(w, "Access to this host is not allowed", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r)
		return
	}

	p.modifyRequest(r)
	p.loadBalance(r)

	if cachedResp, found := p.Cache.Get(r.URL.String()); found {
		cachedResp.(*http.Response).Write(w)
		cacheHits.WithLabelValues(r.Host).Inc()
		return
	}

	resp, err := p.CircuitBreaker.Execute(func() (interface{}, error) {
		return p.Transport.RoundTrip(r)
	})
	if err != nil {
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
		return
	}

	p.modifyResponse(resp.(*http.Response))

	if err := p.compressResponse(w, r, resp.(*http.Response)); err != nil {
		http.Error(w, "Failed to compress response", http.StatusInternalServerError)
		return
	}

	p.Cache.Set(r.URL.String(), resp.(*http.Response), cache.DefaultExpiration)
	requestsTotal.WithLabelValues(r.Method, fmt.Sprint(resp.(*http.Response).StatusCode), r.Host).Inc()

	responseTime := time.Since(start)
	bytesTransferred.WithLabelValues("in", r.Host).Add(float64(resp.(*http.Response).ContentLength))
	p.logRequest(r, resp.(*http.Response).StatusCode, responseTime)
}

func main() {
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	listenAddr := flag.String("listen", fmt.Sprintf(":%d", defaultPort), "Address to listen on for incoming requests")
	flag.Parse()

	proxy, err := NewProxy(*configPath)
	if err != nil {
		logger.Fatalf("Error initializing proxy: %v", err)
	}

	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/", proxy)

	server := &http.Server{Addr: *listenAddr}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Error starting server: %v", err)
		}
	}()

	logger.Printf("Proxy server is listening on %s", *listenAddr)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	logger.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Fatalf("Error shutting down server: %v", err)
	}

	logger.Println("Server gracefully stopped")
}
