package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
	"github.com/patrickmn/go-cache"
)

const (
	bufSize     = 32 * 1024
	defaultPort = 8080
	pac         = `
function FindProxyForURL(url, host) {
	if (isInNet(host, "10.0.0.0", "255.0.0.0")) return "DIRECT";
	return "PROXY 10.0.0.2:8080;";
}`
)

var (
	logger = log.New(os.Stdout, "", log.LstdFlags)

	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of requests processed by the proxy",
		},
		[]string{"method", "status"},
	)
	bytesTransferred = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_bytes_transferred",
			Help: "Total number of bytes transferred through the proxy",
		},
		[]string{"direction"},
	)
	cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "proxy_cache_hits",
			Help: "Total number of cache hits",
		},
	)
)

type Proxy struct {
	Transport   http.RoundTripper
	Credential  string
	Cache       *cache.Cache
	RateLimiter *rate.Limiter
}

func NewProxy() *Proxy {
	return &Proxy{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // Note: This is not recommended for production use
		},
		Cache:       cache.New(5*time.Minute, 10*time.Minute),
		RateLimiter: rate.NewLimiter(rate.Every(time.Second), 100), // 100 requests per second
	}
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

func (p *Proxy) handleTunnel(w http.ResponseWriter, r *http.Request) {
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
	go transfer(&wg, destConn, clientConn)
	go transfer(&wg, clientConn, destConn)
	wg.Wait()
}

func transfer(wg *sync.WaitGroup, destination io.WriteCloser, source io.ReadCloser) {
	defer wg.Done()
	defer destination.Close()
	defer source.Close()
	n, _ := io.Copy(destination, source)
	bytesTransferred.WithLabelValues("out").Add(float64(n))
}

func (p *Proxy) modifyRequest(r *http.Request) {
	// Example: Add a custom header
	r.Header.Add("X-Proxied-By", "GoProxy")

	// Example: Block certain domains
	if strings.Contains(r.Host, "blocked-domain.com") {
		r.URL = nil // This will cause the request to fail
	}
}

func (p *Proxy) modifyResponse(resp *http.Response) {
	// Example: Add a custom header
	resp.Header.Add("X-Proxy-Info", "Modified by GoProxy")

	// Example: Modify content (be careful with this!)
	if resp.Header.Get("Content-Type") == "text/html" {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			modifiedBody := strings.ReplaceAll(string(body), "</body>", "<footer>Modified by GoProxy</footer></body>")
			resp.Body = io.NopCloser(strings.NewReader(modifiedBody))
			resp.ContentLength = int64(len(modifiedBody))
			resp.Header.Set("Content-Length", fmt.Sprint(len(modifiedBody)))
		}
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.handleProxyAuth(w, r) {
		return
	}

	if !p.RateLimiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	logger.Printf("Received request %s %s from %s", r.Method, r.Host, r.RemoteAddr)

	if r.URL.Path == "/pac" {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(pac))
		return
	}

	if r.Method == http.MethodConnect {
		p.handleTunnel(w, r)
		return
	}

	// Check cache
	if cachedResp, found := p.Cache.Get(r.URL.String()); found {
		cacheHits.Inc()
		w.WriteHeader(http.StatusOK)
		w.Write(cachedResp.([]byte))
		return
	}

	p.modifyRequest(r)

	resp, err := p.Transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", http.StatusBadGateway)).Inc()
		return
	}
	defer resp.Body.Close()

	p.modifyResponse(resp)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("Error reading response body: %v", err)
		return
	}

	// Cache the response
	p.Cache.Set(r.URL.String(), body, cache.DefaultExpiration)

	n, _ := w.Write(body)
	bytesTransferred.WithLabelValues("in").Add(float64(n))
	requestsTotal.WithLabelValues(r.Method, fmt.Sprintf("%d", resp.StatusCode)).Inc()
}

func main() {
	addr := flag.String("addr", fmt.Sprintf(":%d", defaultPort), "listen address")
	auth := flag.String("auth", "", "http auth, eg: susan:hello-kitty")
	certFile := flag.String("cert", "", "path to certificate file")
	keyFile := flag.String("key", "", "path to key file")
	flag.Parse()

	prometheus.MustRegister(requestsTotal, bytesTransferred, cacheHits)

	proxy := NewProxy()
	if *auth != "" {
		proxy.Credential = base64.StdEncoding.EncodeToString([]byte(*auth))
	}

	go func() {
		for {
			logger.Printf("Active goroutines: %d", runtime.NumGoroutine())
			time.Sleep(30 * time.Second)
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", proxy)

	server := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}

	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		logger.Println("Shutting down server...")
		if err := server.Shutdown(context.Background()); err != nil {
			logger.Printf("HTTP server Shutdown: %v", err)
		}
	}()

	logger.Printf("Proxy server listening on %s", *addr)
	var err error
	if *certFile != "" && *keyFile != "" {
		err = server.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
}