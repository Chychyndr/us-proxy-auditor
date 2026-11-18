package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseProxy(t *testing.T) {
	tests := []struct {
		raw, defaultScheme, scheme, host string
		port                             int
		ok                               bool
	}{
		{"8.8.8.8:1080", "socks5", "socks5", "8.8.8.8", 1080, true},
		{" http://1.1.1.1:8080 # comment", "socks5", "http", "1.1.1.1", 8080, true},
		{"socks5h://9.9.9.9:9050", "http", "socks5", "9.9.9.9", 9050, true},
		{"127.0.0.1:1080", "socks5", "", "", 0, false},
		{"192.168.1.10:1080", "socks5", "", "", 0, false},
		{"100.64.1.1:1080", "socks5", "", "", 0, false},
		{"169.254.0.1:1080", "socks5", "", "", 0, false},
		{"198.51.100.4:1080", "socks5", "", "", 0, false},
		{"203.0.113.10:1080", "socks5", "", "", 0, false},
		{"2001:4860:4860::8888:1080", "socks5", "", "", 0, false},
		{"http://user:pass@8.8.8.8:1080", "http", "", "", 0, false},
		{"http://8.8.8.8:1080/path", "http", "", "", 0, false},
		{"ftp://8.8.8.8:1080", "http", "", "", 0, false},
		{"8.8.8.8:0", "http", "", "", 0, false},
		{"8.8.8.8:65536", "http", "", "", 0, false},
		{"8.8.8.8:notaport", "http", "", "", 0, false},
		{"# comment", "http", "", "", 0, false},
		{"", "http", "", "", 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			scheme, host, port, ok := parseProxy(tc.raw, tc.defaultScheme)
			if scheme != tc.scheme || host != tc.host || port != tc.port || ok != tc.ok {
				t.Fatalf("got %q %q %d %v, want %q %q %d %v", scheme, host, port, ok, tc.scheme, tc.host, tc.port, tc.ok)
			}
		})
	}
}

func TestParseAndDeduplicateSources(t *testing.T) {
	into := make(map[string]*proxy)
	if got := parseSource("8.8.8.8:1080\n1.1.1.1:80\n8.8.8.8:1080\n", "socks5", "feedA", true, into); got != 2 {
		t.Fatalf("added %d", got)
	}
	if got := parseSource("socks5://8.8.8.8:1080\n", "http", "feedB", false, into); got != 0 {
		t.Fatalf("duplicate added %d", got)
	}
	p := into["socks5://8.8.8.8:1080"]
	if p == nil || !p.USHint || len(p.Sources) != 2 {
		t.Fatalf("bad metadata: %#v", p)
	}
}

func testResult() *result {
	return &result{Proxy: &proxy{Scheme: "socks5", Host: "8.8.8.8", Port: 1080, Sources: map[string]bool{"sourceA": true}}, Status: "pending_geo", Country1: "US", Country2: "US", NetworkType: "possibly_isp", GoogleStatus: "not_checked", HeadersLeak: "not_checked", LatencyMS: 50, Successes: 2, Attempts: 2}
}

func TestGeoStatus(t *testing.T) {
	cases := []struct {
		a, b, network, want string
		exclude             bool
	}{
		{"US", "US", "possibly_isp", "pending_stability", false},
		{"US", "US", "possibly_hosting", "excluded_hosting_hint", true},
		{"US", "", "unknown", "unconfirmed_us", false},
		{"", "", "unknown", "geo_unavailable", false},
		{"US", "CA", "unknown", "geo_disagreement", false},
		{"CA", "CA", "unknown", "not_us", false},
	}
	for _, tc := range cases {
		r := testResult()
		r.Country1 = tc.a
		r.Country2 = tc.b
		r.NetworkType = tc.network
		if got := geoStatus(r, options{ExcludeHosting: tc.exclude}); got != tc.want {
			t.Errorf("geoStatus(%q,%q) = %q want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestOptionalChecksAfterGeo(t *testing.T) {
	r := testResult()
	opts := options{CheckGoogle: true, CheckHeaders: true}
	if geoStatus(r, opts) != "pending_stability" {
		t.Fatal("optional checks rejected before validation")
	}
	r.Status = "pending_stability"
	if got := finalStatus(r, opts); got != "google_not_confirmed" {
		t.Fatalf("unexpected %s", got)
	}
	r.GoogleStatus = "204"
	if got := finalStatus(r, opts); got != "headers_unverified" {
		t.Fatalf("unexpected %s", got)
	}
	r.HeadersLeak = "present"
	if got := finalStatus(r, opts); got != "forwarding_headers" {
		t.Fatalf("unexpected %s", got)
	}
	r.HeadersLeak = "not_seen"
	if got := finalStatus(r, opts); got != "verified_us" {
		t.Fatalf("unexpected %s", got)
	}
}

func TestClassification(t *testing.T) {
	if got := networkType("DataWagon LLC hosting"); got != "possibly_hosting" {
		t.Fatal(got)
	}
	if got := networkType("Comcast Cable"); got != "possibly_isp" {
		t.Fatal(got)
	}
	if got := networkType("Unknown Corp"); got != "unknown" {
		t.Fatal(got)
	}
}

func TestWriteReports(t *testing.T) {
	dir := t.TempDir()
	good := testResult()
	good.Status = "verified_us"
	bad := testResult()
	bad.Proxy = &proxy{Scheme: "http", Host: "1.1.1.1", Port: 80, Sources: map[string]bool{"sourceB": true}}
	bad.Status = "not_us"
	bad.Country1 = "CA"
	bad.Country2 = "CA"
	if err := writeReports([]*result{bad, good}, map[string]feedReport{}, options{Output: dir, Concurrency: 128, GeoRate: 2}, 1.5); err != nil {
		t.Fatal(err)
	}
	expected := []string{"all_results.csv", "verified_us.csv", "verified_us.txt", "verified_http.txt", "verified_socks5.txt", "report.json"}
	for _, name := range expected {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(filepath.Join(dir, "verified_us.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "socks5://8.8.8.8:1080\n" {
		t.Errorf("unexpected verified list: %q", b)
	}
	f, err := os.Open(filepath.Join(dir, "all_results.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || !reflect.DeepEqual(rows[0], fields) {
		t.Errorf("CSV rows: %v", rows)
	}
	meta, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Verified int `json:"verified_us"`
		Checked  int `json:"checked_candidates"`
	}
	if err := json.Unmarshal(meta, &report); err != nil {
		t.Fatal(err)
	}
	if report.Verified != 1 || report.Checked != 2 {
		t.Fatal(report)
	}
}

func TestRunPoolBounded(t *testing.T) {
	var active, max atomic.Int64
	items := make([]int, 42)
	for i := range items {
		items[i] = i
	}
	runPool(context.Background(), 4, items, func(_ context.Context, _ int) {
		n := active.Add(1)
		for {
			old := max.Load()
			if n <= old || max.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(time.Millisecond)
		active.Add(-1)
	})
	if max.Load() > 4 || max.Load() < 1 || active.Load() != 0 {
		t.Fatalf("unbounded concurrency: max=%d active=%d", max.Load(), active.Load())
	}
}

func TestFinalStatusPreservesFailures(t *testing.T) {
	r := testResult()
	r.Status = "unstable"
	if got := finalStatus(r, options{}); got != "unstable" {
		t.Fatal(got)
	}
}

func TestPublicIP(t *testing.T) {
	if publicIP("8.8.4.4\n") != "8.8.4.4" {
		t.Fatal("valid IPv4 rejected")
	}
	for _, invalid := range []string{"127.0.0.1", "192.168.0.1", "203.0.113.4", "garbage"} {
		if publicIP(invalid) != "" {
			t.Errorf("accepted invalid IP %s", invalid)
		}
	}
}

func TestSortedVerified(t *testing.T) {
	a, b, c := testResult(), testResult(), testResult()
	a.Status = "verified_us"
	a.NetworkType = "possibly_hosting"
	b.Status = "not_us"
	c.Status = "verified_us"
	c.NetworkType = "possibly_isp"
	c.Proxy = &proxy{Scheme: "http", Host: "9.9.9.9", Port: 80, Sources: map[string]bool{"one": true}}
	got := sortedVerified([]*result{a, b, c})
	if len(got) != 2 || got[0] != c {
		t.Fatalf("incorrect ranking: %v", got)
	}
}

func TestNoFeedsInputOnly(t *testing.T) {
	f := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(f, []byte("8.8.8.8:1080\n8.8.8.8:1080\n"), 0600); err != nil {
		t.Fatal(err)
	}
	proxies, _, err := fetchSources(context.Background(), options{NoFeeds: true, Input: f, InputProtocol: "socks5", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(proxies) != 1 || !strings.Contains(proxies[0].url(), "8.8.8.8") {
		t.Fatal(proxies)
	}
}
