package bench

import (
	"testing"
	"time"
)

func TestParseBuckets(t *testing.T) {
	input := "0.001, 0.01, 0.1"
	got, err := parseBuckets(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	want := []float64{0.001, 0.01, 0.1}
	if len(got) != len(want) {
		t.Fatalf("expected %d buckets, got %d", len(want), len(got))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("bucket[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseBucketsErrors(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"0.02,0.01",
		"a,b",
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			if _, err := parseBuckets(tc); err == nil {
				t.Fatalf("expected error for %q", tc)
			}
		})
	}
}

func TestValidateRunConfig(t *testing.T) {
	cfg := RunConfig{
		ClusterFile:     "",
		DirectoryPath:   []string{"test"},
		TargetTPS:       1,
		Workers:         1,
		Duration:        time.Second,
		HistogramConfig: "0.01,0.1",
		TxTimeout:       time.Second,
		Logger:          testLogger{t},
		RandSeed:        1,
		Registry:        NewRegistry(),
	}

	if err := validateRunConfig(cfg); err != nil {
		t.Fatalf("expected config to validate, got %v", err)
	}

	cfg.Workers = 0
	if err := validateRunConfig(cfg); err == nil {
		t.Fatalf("expected validation error for workers")
	}
}

func TestShouldLogFailure(t *testing.T) {
	if !shouldLogFailure(1) {
		t.Fatalf("expected true for early failure")
	}
	if shouldLogFailure(11) {
		t.Fatalf("expected false for 11")
	}
	if !shouldLogFailure(2000) {
		t.Fatalf("expected true for 2000")
	}
}

func TestNormalizeDirectory(t *testing.T) {
	dir := normalizeDirectory(nil)
	if len(dir) != 1 || dir[0] == "" {
		t.Fatalf("expected default directory, got %v", dir)
	}

	dir = normalizeDirectory([]string{"a", "b"})
	if len(dir) != 2 || dir[0] != "a" || dir[1] != "b" {
		t.Fatalf("unexpected result: %v", dir)
	}

	dir = normalizeDirectory([]string{" ", "a ", ""})
	if len(dir) != 1 || dir[0] != "a" {
		t.Fatalf("unexpected result after trimming: %v", dir)
	}
}

type testLogger struct {
	t *testing.T
}

func (l testLogger) Printf(format string, args ...any) {
	l.t.Helper()
}
