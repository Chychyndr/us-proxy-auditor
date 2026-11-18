package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// History is append-only JSON Lines so earlier runs remain available even when
// the latest CSV/TXT reports are overwritten by a watch cycle.
type historyRecord struct {
	CheckedAt    time.Time `json:"checked_at_utc"`
	ProxyURL     string    `json:"proxy_url"`
	Status       string    `json:"status"`
	ExitIP       string    `json:"exit_ip,omitempty"`
	LatencyMS    int64     `json:"latency_ms"`
	JitterMS     int64     `json:"jitter_ms"`
	QualityScore int       `json:"quality_score"`
	Failure      string    `json:"failure,omitempty"`
}

type historyStats struct {
	Checks int
	Passed int
}

func historyPath(o options) string {
	if o.HistoryFile != "" {
		return o.HistoryFile
	}
	return filepath.Join(o.Output, "history.jsonl")
}

func loadHistory(path string) (map[string]historyStats, error) {
	stats := make(map[string]historyStats)
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return stats, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 128*1024)
	line := 0
	for scanner.Scan() {
		line++
		data := strings.TrimSpace(scanner.Text())
		if data == "" {
			continue
		}
		var record historyRecord
		if err := json.Unmarshal([]byte(data), &record); err != nil {
			return nil, fmt.Errorf("invalid history line %d: %w", line, err)
		}
		if record.ProxyURL == "" || record.Status == "" {
			return nil, fmt.Errorf("invalid history line %d: missing required fields", line)
		}
		s := stats[record.ProxyURL]
		s.Checks++
		if record.Status == "verified_us" {
			s.Passed++
		}
		stats[record.ProxyURL] = s
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan history: %w", err)
	}
	return stats, nil
}

// The quality score is a transparent 0-100 measurement based only on the
// observed latency, latency variation, and past successful verification rate.
// It does not claim that a proxy can bypass bot checks or is residential.
func qualityScore(r *result, stats historyStats) int {
	if r.Status != "verified_us" {
		return 0
	}
	if stats.Checks == 0 {
		stats = historyStats{Checks: 1, Passed: 1}
	}
	latency := math.Max(0, float64(r.LatencyMS))
	jitter := math.Max(0, float64(r.JitterMS))
	speedPoints := 45.0 / (1.0 + latency/450.0)
	stabilityPoints := 20.0 / (1.0 + jitter/150.0)
	availabilityPoints := 35.0 * float64(stats.Passed) / float64(stats.Checks)
	score := int(math.Round(speedPoints + stabilityPoints + availabilityPoints))
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func applyHistory(results []*result, o options) error {
	stats := make(map[string]historyStats)
	var err error
	if !o.NoHistory {
		stats, err = loadHistory(historyPath(o))
		if err != nil {
			return err
		}
	}
	now := time.Now().UTC()
	records := make([]historyRecord, 0, len(results))
	for _, r := range results {
		if r == nil || r.Proxy == nil {
			return errors.New("incomplete scan: missing result")
		}
		key := r.Proxy.url()
		s := stats[key]
		s.Checks++
		if r.Status == "verified_us" {
			s.Passed++
		}
		stats[key] = s
		r.HistoryChecks = s.Checks
		r.HistoryPassed = s.Passed
		r.HistoryPassRate = 100 * float64(s.Passed) / float64(s.Checks)
		r.QualityScore = qualityScore(r, s)
		records = append(records, historyRecord{
			CheckedAt: now, ProxyURL: key, Status: r.Status, ExitIP: r.ExitIP,
			LatencyMS: r.LatencyMS, JitterMS: r.JitterMS,
			QualityScore: r.QualityScore, Failure: r.Failure,
		})
	}
	if o.NoHistory {
		return nil
	}
	path := historyPath(o)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	writer := bufio.NewWriter(f)
	encoder := json.NewEncoder(writer)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			_ = f.Close()
			return fmt.Errorf("encode history: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		_ = f.Close()
		return fmt.Errorf("write history: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync history: %w", err)
	}
	return f.Close()
}

func watchCandidates(initial []*result) []*proxy {
	candidates := make([]*proxy, 0)
	seen := make(map[string]bool)
	for _, r := range initial {
		if r == nil || r.Status != "verified_us" || r.Proxy == nil {
			continue
		}
		key := r.Proxy.url()
		if !seen[key] {
			seen[key] = true
			candidates = append(candidates, r.Proxy)
		}
	}
	return candidates
}
