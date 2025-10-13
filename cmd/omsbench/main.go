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

	"github.com/example/omsbench/internal/bench"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	defaultWarmupConnections = 4000
	defaultWarmupParallel    = 200
	defaultWarmupKeepAlive   = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "missing subcommand (warmup|run)\n")
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cmd := os.Args[1]
	switch cmd {
	case "warmup":
		runWarmup(ctx, os.Args[2:])
	case "run":
		runBenchmark(ctx, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", cmd)
		os.Exit(2)
	}
}

func runWarmup(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("warmup", flag.ExitOnError)
	dsn := fs.String("dsn", "", "PostgreSQL connection string targeting Aurora DSQL")
	connections := fs.Int("connections", defaultWarmupConnections, "Number of connections to keep warm")
	parallel := fs.Int("parallel", defaultWarmupParallel, "Number of concurrent connection attempts")
	keepAlive := fs.Duration("keepalive", defaultWarmupKeepAlive, "Interval between keep-alive probes")
	queryTimeout := fs.Duration("query-timeout", 5*time.Second, "Timeout per warmup query")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	if strings.TrimSpace(*dsn) == "" {
		log.Fatalf("--dsn is required")
	}

	cfg := bench.WarmupConfig{
		DSN:            *dsn,
		Connections:    *connections,
		Parallelism:    *parallel,
		KeepAlive:      *keepAlive,
		QueryTimeout:   *queryTimeout,
		Logger:         log.New(os.Stdout, "[warmup] ", log.LstdFlags|log.Lmicroseconds),
		ShutdownSignal: make(chan struct{}),
	}

	if err := bench.RunWarmup(ctx, cfg); err != nil {
		log.Fatalf("warmup failed: %v", err)
	}
}

func runBenchmark(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dsn := fs.String("dsn", "", "PostgreSQL connection string targeting Aurora DSQL")
	targetTPS := fs.Float64("tps", 120000, "Target transactions per second")
	workers := fs.Int("workers", 512, "Number of concurrent workers issuing transactions")
	duration := fs.Duration("duration", 15*time.Minute, "Benchmark duration")
	metricsAddr := fs.String("metrics-addr", ":2112", "Prometheus metrics listen address")
	histBuckets := fs.String("histogram-buckets", "0.001,0.005,0.01,0.02,0.04,0.08,0.16", "Comma-separated histogram buckets in seconds")
	queryTimeout := fs.Duration("query-timeout", 5*time.Second, "Timeout per transactional round trip")
	randSeed := fs.Int64("seed", time.Now().UnixNano(), "Random seed for deterministic runs")
	maxConns := fs.Int("max-conns", 4096, "Maximum open connections in the pool")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("failed to parse flags: %v", err)
	}

	if strings.TrimSpace(*dsn) == "" {
		log.Fatalf("--dsn is required")
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
		DSN:             *dsn,
		TargetTPS:       *targetTPS,
		Workers:         *workers,
		Duration:        *duration,
		HistogramConfig: *histBuckets,
		QueryTimeout:    *queryTimeout,
		Logger:          log.New(os.Stdout, "[run] ", log.LstdFlags|log.Lmicroseconds),
		RandSeed:        *randSeed,
		MaxConnections:  *maxConns,
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
