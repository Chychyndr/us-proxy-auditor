// US Proxy Auditor collects public proxies and checks their US exit locations.
// It uses only the Go standard library and runs entirely in a terminal.
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	echoA          = "https://api.ipify.org?format=json"
	echoB          = "https://checkip.amazonaws.com/"
	googleURL      = "https://www.google.com/generate_204"
	headersURL     = "https://httpbin.org/headers"
	maxSourceBytes = 6 << 20
)

type source struct {
	name, endpoint, scheme string
	usHint                 bool
}

var sources = []source{
	{"ProxyScrape US SOCKS5", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/socks5/data.txt", "socks5", true},
	{"ProxyScrape US HTTP", "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/countries/us/http/data.txt", "http", true},
	{"Litport US", "https://raw.githubusercontent.com/litportnet/free-proxy-list/live/proxies/countries/us/all.txt", "http", true},
	{"monosans SOCKS5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5", false},
	{"monosans HTTP", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http", false},
	{"TheSpeedX SOCKS5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5", false},
	{"TheSpeedX HTTP", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http", false},
	{"FusionProxies SOCKS5", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/socks5.txt", "socks5", false},
	{"FusionProxies HTTP", "https://raw.githubusercontent.com/FusionProxies/free-proxy-list/main/proxies/http.txt", "http", false},
	{"proxmint SOCKS5", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt", "socks5", false},
	{"proxmint HTTP", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt", "http", false},
	{"proxio SOCKS5", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt", "socks5", false},
	{"proxio HTTP", "https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt", "http", false},
}

var hostingWords = []string{"hosting", "hostinger", "datacenter", "data center", "cloud", "vultr", "linode", "digitalocean", "ovh", "hetzner", "amazon", "aws", "azure", "microsoft", "google cloud", "leaseweb", "colocation", "colo ", "datawagon", "racknerd", "contabo", "server farm", "servers.com", "compute", "colo-crossing", "dedicated"}
var ispWords = []string{"comcast", "spectrum", "charter", "verizon", "at&t", "att ", "cox communications", "frontier", "centurylink", "lumen", "t-mobile", "tmobile", "optimum", "cablevision", "xfinity", "astound", "windstream", "mediacom", "fiber internet"}

type proxy struct {
	Scheme  string
	Host    string
	Port    int
	Sources map[string]bool
	USHint  bool
}

func (p *proxy) address() string { return net.JoinHostPort(p.Host, strconv.Itoa(p.Port)) }
func (p *proxy) url() string     { return p.Scheme + "://" + p.address() }

type result struct {
	Proxy        *proxy
	Status       string
	ExitIP       string
	Country1     string
	Country2     string
	Organization string
	NetworkType  string
	LatencyMS    int64
	JitterMS     int64
	Successes    int
	Attempts     int
	GoogleStatus string
	HeadersLeak  string
	Failure      string
	QualityScore  int
	HistoryChecks int
	HistoryPassed int
	HistoryPassRate float64
}

type options struct {
	Limit          int
	Concurrency    int
	Timeout        time.Duration
	Rounds         int
	GeoCap         int
	GeoRate        int
	Output         string
	Input          string
	InputProtocol  string
	CheckGoogle    bool
	CheckHeaders   bool
	ExcludeHosting bool
	NoFeeds        bool
	NoHistory      bool
	HistoryFile    string
	WatchInterval  time.Duration
	WatchCycles    int
	WatchProxies   []*proxy
}

func flags() options {
	var o options
	var timeout float64
	var watchInterval string
	flag.IntVar(&o.Limit, "limit", 1500, "maximum proxy candidates to scan (1-10000)")
	flag.IntVar(&o.Concurrency, "concurrency", 128, "parallel proxy checks (1-256)")
	flag.Float64Var(&timeout, "timeout", 5, "per-request timeout in seconds (2-30)")
	flag.IntVar(&o.Rounds, "rounds", 3, "HTTPS echo checks per proxy including the first two (3-8)")
	flag.IntVar(&o.GeoCap, "geo-cap", 300, "maximum distinct exit IPs queried at geolocation providers (1-500)")
	flag.IntVar(&o.GeoRate, "geo-rate", 2, "maximum geolocation provider requests per second (1-5)")
	flag.StringVar(&o.Output, "output", "results", "directory for CSV, TXT and JSON reports")
	flag.StringVar(&o.Input, "input", "", "optional path to a local proxy list")
	flag.StringVar(&o.InputProtocol, "input-protocol", "socks5", "default protocol for scheme-less local endpoints: socks5 or http")
	flag.BoolVar(&o.CheckGoogle, "check-google", false, "require HTTP 204 from Google generate_204")
	flag.BoolVar(&o.CheckHeaders, "check-headers", false, "reject proxies exposing Forwarded/Via headers")
	flag.BoolVar(&o.ExcludeHosting, "exclude-hosting", false, "exclude likely datacenter networks (heuristic)")
	flag.BoolVar(&o.NoFeeds, "no-feeds", false, "use only --input; do not download public lists")
	flag.BoolVar(&o.NoHistory, "no-history", false, "disable history persistence (quality scores use only the current check)")
	flag.StringVar(&o.HistoryFile, "history-file", "", "custom JSONL history file (default: OUTPUT/history.jsonl)")
	flag.StringVar(&watchInterval, "watch-interval", "", "periodically recheck all initially verified proxies (example: 15m)")
	flag.IntVar(&o.WatchCycles, "watch-cycles", 0, "total scans in watch mode including the first (0 = unlimited)")
	flag.Parse()
	if watchInterval != "" {
		interval, err := time.ParseDuration(watchInterval)
		if err != nil || interval < 30*time.Second {
			fmt.Fprintln(os.Stderr, "--watch-interval must be at least 30s (example: 15m)")
			os.Exit(2)
		}
		o.WatchInterval = interval
	}
	if o.WatchCycles < 0 || (o.WatchCycles != 0 && o.WatchInterval == 0) {
		fmt.Fprintln(os.Stderr, "--watch-cycles requires --watch-interval and must be nonnegative")
		os.Exit(2)
	}
	if o.Limit < 1 || o.Limit > 10000 || o.Concurrency < 1 || o.Concurrency > 256 || timeout < 2 || timeout > 30 || o.Rounds < 3 || o.Rounds > 8 || o.GeoCap < 1 || o.GeoCap > 500 || o.GeoRate < 1 || o.GeoRate > 5 || !slices.Contains([]string{"socks5", "http"}, o.InputProtocol) || (o.NoFeeds && o.Input == "") {
		fmt.Fprintln(os.Stderr, "Invalid settings. Run with --help to inspect parameter limits.")
		os.Exit(2)
	}
	o.Timeout = time.Duration(timeout * float64(time.Second))
	return o
}

// parseProxy accepts public IPv4 endpoint literals without credentials.
func parseProxy(s, defaultScheme string) (string, string, int, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "\ufeff"))
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "//") {
		return "", "", 0, false
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if !strings.Contains(s, "://") {
		s = defaultScheme + "://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", "", 0, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "socks5" && scheme != "socks5h" {
		return "", "", 0, false
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || isSpecialUseIPv4(ip.To4()) {
		return "", "", 0, false
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", "", 0, false
	}
	if scheme == "socks5h" {
		scheme = "socks5"
	}
	return scheme, ip.String(), port, true
}

// IsGlobalUnicast also accepts RFC1918 and some reserved ranges; reject those.
func isSpecialUseIPv4(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	b := ip.To4()
	if b == nil {
		return true
	}
	if b[0] == 0 || b[0] == 10 || b[0] == 127 || b[0] >= 224 || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 169 && b[1] == 254) || (b[0] == 192 && b[1] == 0 && b[2] == 0) || (b[0] == 192 && b[1] == 0 && b[2] == 2) || (b[0] == 192 && b[1] == 88 && b[2] == 99) || (b[0] == 198 && b[1] == 18) || (b[0] == 198 && b[1] == 19) || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113) {
		return true
	}
	return false
}

func parseSource(content, scheme, origin string, usHint bool, into map[string]*proxy) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 128*1024)
	lines := 0
	for scanner.Scan() && lines < 60000 {
		lines++
		kind, host, port, ok := parseProxy(scanner.Text(), scheme)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s://%s:%d", kind, host, port)
		p, exists := into[key]
		if !exists {
			p = &proxy{Scheme: kind, Host: host, Port: port, Sources: map[string]bool{}}
			into[key] = p
			added++
		}
		p.Sources[origin] = true
		p.USHint = p.USHint || usHint
	}
	return added
}

func newDirectClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 32, MaxIdleConnsPerHost: 8, IdleConnTimeout: 15 * time.Second, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 15 * time.Second}).DialContext}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

func proxyClient(p *proxy, timeout time.Duration) (*http.Client, error) {
	u, err := url.Parse(p.url())
	if err != nil {
		return nil, err
	}
	t := &http.Transport{Proxy: http.ProxyURL(u), MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: 10 * time.Second, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DialContext: (&net.Dialer{Timeout: timeout, KeepAlive: 10 * time.Second}).DialContext}
	return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func closeClient(c *http.Client) {
	if t, ok := c.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
func request(ctx context.Context, client *http.Client, address string, maxBytes int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "US-Proxy-Auditor/2.0 (public-proxy-health-check)")
	r, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, r.StatusCode, err
	}
	if len(data) > int(maxBytes) {
		return nil, r.StatusCode, errors.New("response_too_large")
	}
	if r.StatusCode < 200 || r.StatusCode >= 300 {
		return nil, r.StatusCode, fmt.Errorf("HTTP_%d", r.StatusCode)
	}
	return data, r.StatusCode, nil
}

func publicIP(raw string) string {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil || ip.To4() == nil || !ip.IsGlobalUnicast() || isSpecialUseIPv4(ip.To4()) {
		return ""
	}
	return ip.String()
}
func ipEcho(ctx context.Context, c *http.Client, endpoint string) (string, int64, error) {
	before := time.Now()
	b, _, err := request(ctx, c, endpoint, 1024)
	if err != nil {
		return "", 0, err
	}
	var ip string
	if endpoint == echoA {
		var obj struct {
			IP string `json:"ip"`
		}
		if json.Unmarshal(b, &obj) == nil {
			ip = obj.IP
		}
	} else {
		ip = string(b)
	}
	ip = publicIP(ip)
	if ip == "" {
		return "", 0, errors.New("invalid_echo_ip")
	}
	return ip, time.Since(before).Milliseconds(), nil
}
func errorName(err error) string {
	if err == nil {
		return ""
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls:"):
		return "TLS_certificate_invalid"
	case strings.Contains(s, "deadline") || strings.Contains(s, "timeout"):
		return "Timeout"
	case strings.Contains(s, "connection refused"):
		return "Connection_refused"
	case strings.Contains(s, "proxyconnect"):
		return "Proxy_connect_failed"
	case strings.Contains(s, "http_"):
		if i := strings.Index(s, "http_"); i >= 0 {
			return strings.ToUpper(s[i:])
		}
	default:
		return "Network_error"
	}
	return "Network_error"
}

func checkOne(ctx context.Context, p *proxy, timeout time.Duration, directIP string) *result {
	r := &result{Proxy: p, Status: "connection_failed", NetworkType: "unknown", GoogleStatus: "not_checked", HeadersLeak: "not_checked", LatencyMS: -1, JitterMS: -1}
	// A short TCP preflight rejects unreachable endpoints without creating TLS sessions.
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", p.address())
	if err != nil {
		r.Failure = errorName(err)
		return r
	}
	_ = connection.Close()
	client, err := proxyClient(p, timeout)
	if err != nil {
		r.Failure = errorName(err)
		return r
	}
	defer closeClient(client)
	ip1, ms1, e1 := ipEcho(ctx, client, echoA)
	r.Attempts++
	if e1 != nil {
		r.Failure = errorName(e1)
		return r
	}
	r.Successes++
	ip2, ms2, e2 := ipEcho(ctx, client, echoB)
	r.Attempts++
	if e2 != nil {
		r.Failure = errorName(e2)
		return r
	}
	r.Successes++
	r.ExitIP = ip1
	r.LatencyMS = (ms1 + ms2) / 2
	if ms1 > ms2 {
		r.JitterMS = ms1 - ms2
	} else {
		r.JitterMS = ms2 - ms1
	}
	switch {
	case ip1 != ip2:
		r.Status = "exit_ip_changed"
	case directIP != "" && ip1 == directIP:
		r.Status = "same_as_direct_ip"
	default:
		r.Status = "pending_geo"
	}
	return r
}

func networkType(org string) string {
	low := strings.ToLower(org)
	for _, word := range hostingWords {
		if strings.Contains(low, word) {
			return "possibly_hosting"
		}
	}
	for _, word := range ispWords {
		if strings.Contains(low, word) {
			return "possibly_isp"
		}
	}
	return "unknown"
}

type geoData struct{ A, B, Org string }

func lookupGeo(ctx context.Context, client *http.Client, ip string, permits <-chan time.Time) geoData {
	var g geoData
	// Requests are made directly; country hints from source lists are never trusted.
	select {
	case <-ctx.Done():
		return g
	case <-permits:
	}
	if raw, _, err := request(ctx, client, "https://ipwho.is/"+ip, 16*1024); err == nil {
		var d struct {
			Success    bool   `json:"success"`
			Country    string `json:"country_code"`
			Connection struct {
				Org string `json:"org"`
				ISP string `json:"isp"`
			} `json:"connection"`
		}
		if json.Unmarshal(raw, &d) == nil && d.Success {
			g.A = strings.ToUpper(d.Country)
			g.Org = d.Connection.Org
			if g.Org == "" {
				g.Org = d.Connection.ISP
			}
		}
	}
	select {
	case <-ctx.Done():
		return g
	case <-permits:
	}
	if raw, _, err := request(ctx, client, "https://ipapi.co/"+ip+"/json/", 16*1024); err == nil {
		var d struct {
			Country string `json:"country_code"`
			Org     string `json:"org"`
			Error   bool   `json:"error"`
		}
		if json.Unmarshal(raw, &d) == nil && !d.Error {
			g.B = strings.ToUpper(d.Country)
			if g.Org == "" {
				g.Org = d.Org
			}
		}
	}
	return g
}

func geoStatus(r *result, o options) string {
	if r.Status != "pending_geo" {
		return r.Status
	}
	switch {
	case r.Country1 == "US" && r.Country2 == "US": // continue
	case r.Country1 == "" && r.Country2 == "":
		return "geo_unavailable"
	case r.Country1 != "" && r.Country2 != "" && r.Country1 != r.Country2:
		return "geo_disagreement"
	case r.Country1 == "US" || r.Country2 == "US":
		return "unconfirmed_us"
	default:
		return "not_us"
	}
	if o.ExcludeHosting && r.NetworkType == "possibly_hosting" {
		return "excluded_hosting_hint"
	}
	return "pending_stability"
}

func finalStatus(r *result, o options) string {
	if r.Status != "pending_stability" {
		return r.Status
	}
	if o.CheckGoogle && r.GoogleStatus != "204" {
		return "google_not_confirmed"
	}
	if o.CheckHeaders && r.HeadersLeak == "present" {
		return "forwarding_headers"
	}
	if o.CheckHeaders && r.HeadersLeak != "not_seen" {
		return "headers_unverified"
	}
	return "verified_us"
}

func checkStability(ctx context.Context, r *result, o options) {
	client, err := proxyClient(r.Proxy, o.Timeout)
	if err != nil {
		r.Status = "unstable"
		r.Failure = errorName(err)
		return
	}
	defer closeClient(client)
	samples := []int64{r.LatencyMS}
	for i := 0; i < o.Rounds-2; i++ {
		r.Attempts++
		ip, latency, err := ipEcho(ctx, client, echoA)
		if err != nil {
			r.Status = "unstable"
			r.Failure = errorName(err)
			return
		}
		if ip != r.ExitIP {
			r.Status = "exit_ip_changed"
			return
		}
		r.Successes++
		samples = append(samples, latency)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	r.LatencyMS = samples[len(samples)/2]
	r.JitterMS = samples[len(samples)-1] - samples[0]
	if o.CheckHeaders {
		if raw, _, err := request(ctx, client, headersURL, 16*1024); err == nil {
			var d struct {
				Headers map[string]string `json:"headers"`
			}
			if json.Unmarshal(raw, &d) == nil {
				r.HeadersLeak = "not_seen"
				for k := range d.Headers {
					if slices.Contains([]string{"forwarded", "via", "x-forwarded-for", "x-real-ip"}, strings.ToLower(k)) {
						r.HeadersLeak = "present"
						break
					}
				}
			} else {
				r.HeadersLeak = "unknown"
			}
		} else {
			r.HeadersLeak = "unknown"
		}
	}
	if o.CheckGoogle {
		_, code, err := request(ctx, client, googleURL, 1024)
		if err == nil || code != 0 {
			r.GoogleStatus = strconv.Itoa(code)
		} else {
			r.GoogleStatus = "error"
		}
	}
	r.Status = finalStatus(r, o)
}

type feedReport struct {
	Candidates int    `json:"new_candidates"`
	Lines      int    `json:"downloaded_lines"`
	Error      string `json:"error,omitempty"`
}

func fetchSources(ctx context.Context, o options) ([]*proxy, map[string]feedReport, error) {
	candidates := make(map[string]*proxy)
	reports := make(map[string]feedReport)
	if !o.NoFeeds {
		client := newDirectClient(20 * time.Second)
		defer closeClient(client)
		type fetch struct {
			source source
			raw    string
			err    error
		}
		out := make(chan fetch, len(sources))
		sem := make(chan struct{}, 5)
		var wg sync.WaitGroup
		for _, s := range sources {
			wg.Add(1)
			go func(s source) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				b, _, err := request(ctx, client, s.endpoint, maxSourceBytes)
				out <- fetch{s, string(b), err}
			}(s)
		}
		wg.Wait()
		close(out)
		for f := range out {
			if f.err != nil {
				reports[f.source.name] = feedReport{Error: errorName(f.err)}
				fmt.Printf("  [source] %-23s failed\n", f.source.name)
				continue
			}
			n := parseSource(f.raw, f.source.scheme, f.source.name, f.source.usHint, candidates)
			reports[f.source.name] = feedReport{Candidates: n, Lines: strings.Count(f.raw, "\n") + 1}
			fmt.Printf("  [source] %-23s +%d\n", f.source.name, n)
		}
	}
	if o.Input != "" {
		f, err := os.ReadFile(o.Input)
		if err != nil {
			return nil, reports, fmt.Errorf("read --input: %w", err)
		}
		n := parseSource(string(f), o.InputProtocol, "local:"+filepath.Base(o.Input), false, candidates)
		reports["local:"+filepath.Base(o.Input)] = feedReport{Candidates: n, Lines: strings.Count(string(f), "\n") + 1}
		fmt.Printf("  [file] %s: +%d\n", filepath.Base(o.Input), n)
	}
	ordered := make([]*proxy, 0, len(candidates))
	for _, p := range candidates {
		ordered = append(ordered, p)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		if a.USHint != b.USHint {
			return a.USHint
		}
		if len(a.Sources) != len(b.Sources) {
			return len(a.Sources) > len(b.Sources)
		}
		if a.Scheme != b.Scheme {
			return a.Scheme == "socks5"
		}
		return a.url() < b.url()
	})
	if len(ordered) > o.Limit {
		ordered = ordered[:o.Limit]
	}
	return ordered, reports, nil
}

// runPool uses a bounded worker pool; no goroutine is created per candidate.
func runPool[T any](ctx context.Context, concurrency int, items []T, fn func(context.Context, T)) {
	jobs := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				fn(ctx, item)
			}
		}()
	}
	for _, item := range items {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
}

func sortedVerified(rs []*result) []*result {
	verified := make([]*result, 0)
	for _, r := range rs {
		if r.Status == "verified_us" {
			verified = append(verified, r)
		}
	}
	sort.Slice(verified, func(i, j int) bool {
		a, b := verified[i], verified[j]
		tier := func(s string) int {
			switch s {
			case "possibly_isp":
				return 0
			case "unknown":
				return 1
			default:
				return 2
			}
		}
		if a.QualityScore != b.QualityScore {
			return a.QualityScore > b.QualityScore
		}
		if tier(a.NetworkType) != tier(b.NetworkType) {
			return tier(a.NetworkType) < tier(b.NetworkType)
		}
		if len(a.Proxy.Sources) != len(b.Proxy.Sources) {
			return len(a.Proxy.Sources) < len(b.Proxy.Sources)
		}
		if a.LatencyMS != b.LatencyMS {
			return a.LatencyMS < b.LatencyMS
		}
		return a.Proxy.url() < b.Proxy.url()
	})
	return verified
}

var fields = []string{"status", "protocol", "host", "port", "proxy_url", "exit_ip", "country_1", "country_2", "organization", "network_type_hint", "latency_ms", "jitter_ms", "successes", "attempts", "google_http_status", "headers_leak", "sources_count", "sources", "failure", "quality_score", "history_checks", "history_passed", "history_pass_rate_pct"}

func csvRecord(r *result) []string {
	names := make([]string, 0, len(r.Proxy.Sources))
	for name := range r.Proxy.Sources {
		names = append(names, name)
	}
	sort.Strings(names)
	return []string{r.Status, r.Proxy.Scheme, r.Proxy.Host, strconv.Itoa(r.Proxy.Port), r.Proxy.url(), r.ExitIP, r.Country1, r.Country2, r.Organization, r.NetworkType, strconv.FormatInt(r.LatencyMS, 10), strconv.FormatInt(r.JitterMS, 10), strconv.Itoa(r.Successes), strconv.Itoa(r.Attempts), r.GoogleStatus, r.HeadersLeak, strconv.Itoa(len(names)), strings.Join(names, "; "), r.Failure, strconv.Itoa(r.QualityScore), strconv.Itoa(r.HistoryChecks), strconv.Itoa(r.HistoryPassed), fmt.Sprintf("%.1f", r.HistoryPassRate)}
}
func writeCSV(path string, results []*result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err = w.Write(fields); err != nil {
		return err
	}
	for _, r := range results {
		if err = w.Write(csvRecord(r)); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
func writeTXT(path string, rs []*result, scheme string) error {
	var b strings.Builder
	for _, r := range rs {
		if scheme == "" || r.Proxy.Scheme == scheme {
			b.WriteString(r.Proxy.url())
			b.WriteByte('\n')
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}
func writeReports(results []*result, sourceInfo map[string]feedReport, o options, seconds float64) error {
	if err := os.MkdirAll(o.Output, 0755); err != nil {
		return err
	}
	verified := sortedVerified(results)
	all := append([]*result(nil), results...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].Status != all[j].Status {
			if all[i].Status == "verified_us" {
				return true
			}
			if all[j].Status == "verified_us" {
				return false
			}
			return all[i].Status < all[j].Status
		}
		return all[i].Proxy.url() < all[j].Proxy.url()
	})
	for _, job := range []struct {
		name string
		rs   []*result
	}{{"all_results.csv", all}, {"verified_us.csv", verified}} {
		if err := writeCSV(filepath.Join(o.Output, job.name), job.rs); err != nil {
			return err
		}
	}
	for _, job := range []struct{ name, scheme string }{{"verified_us.txt", ""}, {"verified_socks5.txt", "socks5"}, {"verified_http.txt", "http"}} {
		if err := writeTXT(filepath.Join(o.Output, job.name), verified, job.scheme); err != nil {
			return err
		}
	}
	counts := make(map[string]int)
	for _, r := range results {
		counts[r.Status]++
	}
	report := map[string]any{
		"created_at_utc": time.Now().UTC().Format(time.RFC3339), "duration_seconds": seconds,
		"checked_candidates": len(results), "verified_us": len(verified), "status_counts": counts, "sources": sourceInfo,
		"settings": map[string]any{"limit": o.Limit, "concurrency": o.Concurrency, "timeout_seconds": o.Timeout.Seconds(), "rounds": o.Rounds, "geo_cap": o.GeoCap, "geo_rate": o.GeoRate, "check_google": o.CheckGoogle, "check_headers": o.CheckHeaders, "exclude_hosting": o.ExcludeHosting, "history_enabled": !o.NoHistory, "watch_interval": o.WatchInterval.String(), "watch_cycles": o.WatchCycles},
		"caveats":  []string{"Public proxies are untrusted. Never transmit credentials through them.", "Geo location requires agreement from two providers; it is not a physical-location guarantee.", "Network-type classification is heuristic, and appearances in lists do not establish real-world popularity.", "Website bot checks, WebRTC leakage, and browser fingerprints are outside this tool's scope."},
	}
	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(o.Output, "report.json"), append(b, '\n'), 0644)
}

func run(ctx context.Context, o options) ([]*result, error) {
	started := time.Now()
	var proxies []*proxy
	sourceInfo := make(map[string]feedReport)
	if o.WatchProxies != nil {
		proxies = o.WatchProxies
		fmt.Printf("[1/4] Rechecking %d retained proxy candidates...\n", len(proxies))
		sourceInfo["watch_recheck"] = feedReport{Candidates: len(proxies)}
	} else {
		fmt.Println("[1/4] Collecting public proxy lists...")
		var err error
		proxies, sourceInfo, err = fetchSources(ctx, o)
		if err != nil {
			return nil, err
		}
	}
	if len(proxies) == 0 {
		return nil, errors.New("no proxy candidates found; try --input or check source availability")
	}
	fmt.Printf("Unique candidates to test: %d\n", len(proxies))
	directClient := newDirectClient(o.Timeout)
	directIP, _, err := ipEcho(ctx, directClient, echoA)
	closeClient(directClient)
	if err != nil {
		directIP = ""
	}
	if directIP == "" {
		fmt.Println("Direct-IP check unavailable; same-IP detection will be inconclusive")
	}
	fmt.Println("[2/4] Checking TCP, HTTPS certificates and two independent IP echoes...")
	results := make([]*result, len(proxies))
	indexes := make([]int, len(proxies))
	for i := range indexes {
		indexes[i] = i
	}
	var completed atomic.Int64
	runPool(ctx, o.Concurrency, indexes, func(ctx context.Context, i int) {
		results[i] = checkOne(ctx, proxies[i], o.Timeout, directIP)
		n := completed.Add(1)
		if n%100 == 0 || int(n) == len(indexes) {
			fmt.Printf("  Checked %d/%d\n", n, len(indexes))
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	candidates := make([]*result, 0)
	for _, r := range results {
		if r.Status == "pending_geo" {
			candidates = append(candidates, r)
		}
	}
	fmt.Printf("Passed initial checks: %d\n", len(candidates))
	fmt.Println("[3/4] Confirming US geolocation via two independent APIs...")
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.Proxy.USHint != b.Proxy.USHint {
			return a.Proxy.USHint
		}
		return a.LatencyMS < b.LatencyMS
	})
	ipList := make([]string, 0)
	seen := make(map[string]bool)
	for _, r := range candidates {
		if !seen[r.ExitIP] {
			seen[r.ExitIP] = true
			ipList = append(ipList, r.ExitIP)
		}
	}
	if len(ipList) > o.GeoCap {
		ipList = ipList[:o.GeoCap]
	}
	geos := make(map[string]geoData)
	var geoMu sync.Mutex
	geoClient := newDirectClient(o.Timeout)
	// Shared ticker limits aggregate traffic to rate-limited third-party geolocation APIs.
	permits := time.NewTicker(time.Second / time.Duration(o.GeoRate))
	runPool(ctx, 2, ipList, func(ctx context.Context, ip string) {
		g := lookupGeo(ctx, geoClient, ip, permits.C)
		geoMu.Lock()
		geos[ip] = g
		geoMu.Unlock()
	})
	permits.Stop()
	closeClient(geoClient)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	eligible := make([]*result, 0)
	for _, r := range candidates {
		if g, ok := geos[r.ExitIP]; ok {
			r.Country1 = g.A
			r.Country2 = g.B
			r.Organization = g.Org
			r.NetworkType = networkType(g.Org)
		}
		r.Status = geoStatus(r, o)
		if r.Status == "pending_stability" {
			eligible = append(eligible, r)
		}
	}
	fmt.Printf("Provisional verified US: %d\n", len(eligible))
	fmt.Println("[4/4] Rechecking stability and optional endpoints...")
	completed.Store(0)
	runPool(ctx, o.Concurrency, eligible, func(ctx context.Context, r *result) {
		checkStability(ctx, r, o)
		n := completed.Add(1)
		if n%25 == 0 || int(n) == len(eligible) {
			fmt.Printf("  Rechecked %d/%d\n", n, len(eligible))
		}
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	elapsed := time.Since(started).Seconds()
	if err := applyHistory(results, o); err != nil {
		return nil, err
	}
	if err := writeReports(results, sourceInfo, o, elapsed); err != nil {
		return nil, err
	}
	verified := sortedVerified(results)
	fmt.Printf("\nCompleted in %.1fs: %d candidates, %d strictly verified US proxies.\n", elapsed, len(results), len(verified))
	for i, r := range verified {
		if i >= 10 {
			break
		}
		fmt.Printf("  %-34s score %3d | %5d ms | %-17s | %.40s\n", r.Proxy.url(), r.QualityScore, r.LatencyMS, r.NetworkType, r.Organization)
	}
	absolute, _ := filepath.Abs(o.Output)
	fmt.Println("Results:", absolute)
	return results, nil
}

func main() {
	o := flags()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	results, err := run(ctx, o)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Println("\nScan interrupted.")
			return
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	if o.WatchInterval <= 0 || o.WatchCycles == 1 {
		return
	}
	candidates := watchCandidates(results)
	if len(candidates) == 0 {
		fmt.Println("Watch mode stopped: no strictly verified US proxies from the initial scan.")
		return
	}
	fmt.Printf("Watch mode enabled: retaining %d proxies; rechecking every %s. Press Ctrl+C to stop.\n", len(candidates), o.WatchInterval)
	for cycle := 2; o.WatchCycles == 0 || cycle <= o.WatchCycles; cycle++ {
		timer := time.NewTimer(o.WatchInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			fmt.Println("\nWatch mode stopped.")
			return
		case <-timer.C:
		}
		fmt.Printf("\n[watch] Starting scan %d...\n", cycle)
		next := o
		next.WatchProxies = candidates
		_, err := run(ctx, next)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				fmt.Println("\nWatch mode stopped.")
				return
			}
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
	}
}
