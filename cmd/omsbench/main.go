package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Abdullah1738/omsbench/internal/bench"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	args := os.Args[1:]
	if len(args) == 0 {
		runBenchmark(ctx, args)
		return
	}

	switch args[0] {
	case "run":
		runBenchmark(ctx, args[1:])
	case "warmup":
		log.Println("FoundationDB benchmark does not require a warmup phase; exiting.")
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		os.Exit(2)
	}
}

func runBenchmark(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	clusterFile := fs.String("cluster-file", "", "Path to FoundationDB cluster file; defaults to FDB_CLUSTER_FILE env var")
	apiVersion := fs.Int("api-version", bench.DefaultAPIVersion, "FoundationDB API version to negotiate")
	namespace := fs.String("namespace", "omsbench", "Slash- or dot-delimited subspace namespace for benchmark keys")
	targetTPS := fs.Float64("tps", 120000, "Target transactions per second")
	workers := fs.Int("workers", 512, "Number of concurrent workers issuing transactions")
	duration := fs.Duration("duration", 15*time.Minute, "Benchmark duration")
	metricsAddr := fs.String("metrics-addr", ":2112", "Prometheus metrics listen address")
	histBuckets := fs.String("histogram-buckets", "0.001,0.005,0.01,0.02,0.04,0.08,0.16", "Comma-separated histogram buckets in seconds")
	txTimeout := fs.Duration("tx-timeout", 5*time.Second, "Timeout per FoundationDB transaction")
	randSeed := fs.Int64("seed", time.Now().UnixNano(), "Random seed for deterministic runs")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	registry := bench.NewRegistry()
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})

	httpSrv := &http.Server{
		Addr:         *metricsAddr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		Handler:      handler,
	}

	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics HTTP server error: %v", err)
		}
	}()

	cfg := bench.RunConfig{
		ClusterFile:     *clusterFile,
		DirectoryPath:   parseNamespace(*namespace),
		APIVersion:      *apiVersion,
		TargetTPS:       *targetTPS,
		Workers:         *workers,
		Duration:        *duration,
		HistogramConfig: *histBuckets,
		TxTimeout:       *txTimeout,
		Logger:          log.New(os.Stdout, "[run] ", log.LstdFlags|log.Lmicroseconds),
		RandSeed:        *randSeed,
		Registry:        registry,
	}

	err := bench.RunBenchmark(ctx, cfg)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("metrics server shutdown error: %v", err)
	}

	if err != nil {
		log.Fatalf("benchmark failed: %v", err)
	}
}

func parseNamespace(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}

	fields := strings.FieldsFunc(trimmed, func(r rune) bool {
		switch r {
		case '/', '.', ':':
			return true
		default:
			return false
		}
	})

	out := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		out = append(out, field)
	}
	return out
}
