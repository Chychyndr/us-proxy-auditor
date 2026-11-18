package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func verifiedFixture() *result {
	r := testResult()
	r.Status = "verified_us"
	r.LatencyMS = 120
	r.JitterMS = 25
	r.Attempts = 3
	r.Successes = 3
	return r
}

func TestHistoryAcrossRepeatedScans(t *testing.T) {
	dir := t.TempDir()
	o := options{Output: dir}
	first := verifiedFixture()
	if err := applyHistory([]*result{first}, o); err != nil {
		t.Fatal(err)
	}
	if first.HistoryChecks != 1 || first.HistoryPassed != 1 || first.HistoryPassRate != 100 || first.QualityScore <= 0 {
		t.Fatalf("incorrect first history values: %+v", first)
	}
	firstScore := first.QualityScore
	failed := verifiedFixture()
	failed.Status = "unstable"
	failed.Failure = "Timeout"
	if err := applyHistory([]*result{failed}, o); err != nil {
		t.Fatal(err)
	}
	if failed.HistoryChecks != 2 || failed.HistoryPassed != 1 || failed.HistoryPassRate != 50 || failed.QualityScore != 0 {
		t.Fatalf("failed check should count but not score: %+v", failed)
	}
	third := verifiedFixture()
	if err := applyHistory([]*result{third}, o); err != nil {
		t.Fatal(err)
	}
	if third.HistoryChecks != 3 || third.HistoryPassed != 2 || third.QualityScore >= firstScore {
		t.Fatalf("history did not lower reliability score: %+v", third)
	}
	stats, err := loadHistory(historyPath(o))
	if err != nil {
		t.Fatal(err)
	}
	got := stats[first.Proxy.url()]
	if got.Checks != 3 || got.Passed != 2 {
		t.Fatalf("wrong persisted history: %+v", got)
	}
	f, err := os.Open(historyPath(o))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var record historyRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record.ProxyURL != first.Proxy.url() || record.CheckedAt.IsZero() {
			t.Fatalf("invalid record: %+v", record)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected 3 records, got %d", count)
	}
}

func TestQualityScoreSpeedAndJitter(t *testing.T) {
	a := verifiedFixture()
	b := verifiedFixture()
	b.LatencyMS = 1700
	b.JitterMS = 700
	s := historyStats{Checks: 5, Passed: 5}
	if qualityScore(a, s) <= qualityScore(b, s) {
		t.Fatalf("fast stable proxy should outrank slow unstable proxy: %d vs %d", qualityScore(a, s), qualityScore(b, s))
	}
	if qualityScore(a, historyStats{Checks: 10, Passed: 5}) >= qualityScore(a, s) {
		t.Fatal("history availability must affect quality score")
	}
	b.Status = "connection_failed"
	if qualityScore(b, s) != 0 {
		t.Fatal("failed proxy must score zero")
	}
}

func TestHistoryDisabledAndCustomPath(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom", "audit.jsonl")
	r := verifiedFixture()
	if err := applyHistory([]*result{r}, options{Output: dir, NoHistory: true}); err != nil {
		t.Fatal(err)
	}
	if r.HistoryChecks != 1 || r.HistoryPassRate != 100 {
		t.Fatalf("no-history scoring must still work: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(dir, "history.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("no-history wrote a file: %v", err)
	}
	if err := applyHistory([]*result{verifiedFixture()}, options{Output: dir, HistoryFile: custom}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(custom); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryMalformedFailsClearly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	if err := os.WriteFile(path, []byte("{broken\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyHistory([]*result{verifiedFixture()}, options{Output: dir}); err == nil || !strings.Contains(err.Error(), "history line") {
		t.Fatalf("malformed history silently accepted: %v", err)
	}
}

func TestWatchCandidatesStableAndDeduplicated(t *testing.T) {
	good := verifiedFixture()
	bad := verifiedFixture()
	bad.Status = "connection_failed"
	other := verifiedFixture()
	other.Proxy = &proxy{Scheme: "http", Host: "9.9.9.9", Port: 8000}
	got := watchCandidates([]*result{bad, good, nil, good, other})
	if len(got) != 2 || got[0].url() != good.Proxy.url() || got[1].url() != other.Proxy.url() {
		t.Fatalf("incorrect retained watch candidates: %v", got)
	}
}

func TestHistoryCSVAndQualityRanking(t *testing.T) {
	first := verifiedFixture()
	second := verifiedFixture()
	second.Proxy = &proxy{Scheme: "http", Host: "9.9.9.9", Port: 8080}
	first.QualityScore = 40
	second.QualityScore = 85
	sorted := sortedVerified([]*result{first, second})
	if len(sorted) != 2 || sorted[0] != second {
		t.Fatalf("quality did not drive ranking: %v", sorted)
	}
	row := csvRecord(second)
	if len(row) != len(fields) || fields[len(fields)-4] != "quality_score" {
		t.Fatalf("CSV quality fields missing: %v", fields)
	}
}
