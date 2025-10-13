package bench

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// WarmupConfig configures the warmup workflow.
type WarmupConfig struct {
	DSN            string
	Connections    int
	Parallelism    int
	KeepAlive      time.Duration
	QueryTimeout   time.Duration
	Logger         Logger
	ShutdownSignal <-chan struct{}
}

// RunConfig configures the benchmark workload.
type RunConfig struct {
	DSN             string
	TargetTPS       float64
	Workers         int
	Duration        time.Duration
	HistogramConfig string
	QueryTimeout    time.Duration
	Logger          Logger
	RandSeed        int64
	MaxConnections  int
	Registry        *prometheus.Registry
}

// Logger captures the log.Printf signature we rely on.
type Logger interface {
	Printf(format string, args ...any)
}

// ErrInvalidConfig indicates validation failure.
var ErrInvalidConfig = errors.New("invalid configuration")

// NewRegistry creates a metrics registry with default collectors installed.
func NewRegistry() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return reg
}

// RunWarmup warms up connections by opening and holding connections to the
// Aurora DSQL cluster until the context is cancelled.
func RunWarmup(ctx context.Context, cfg WarmupConfig) error {
	if err := validateWarmupConfig(cfg); err != nil {
		return err
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return fmt.Errorf("parse dsn: %w", err)
	}

	if cfg.Connections > 0 {
		poolCfg.MaxConns = int32(cfg.Connections)
		poolCfg.MinConns = int32(cfg.Connections)
	}
	poolCfg.HealthCheckPeriod = cfg.KeepAlive
	poolCfg.MaxConnIdleTime = cfg.KeepAlive * 2
	poolCfg.ConnConfig.ConnectTimeout = cfg.QueryTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create pool: %w", err)
	}
	defer pool.Close()

	cfg.Logger.Printf("warming %d connections (parallelism=%d)", cfg.Connections, cfg.Parallelism)

	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(cfg.Parallelism)

	var (
		heldConns []*pgxpool.Conn
		heldMu    sync.Mutex
	)

	for i := 0; i < cfg.Connections; i++ {
		index := i
		group.Go(func() error {
			acquireCtx, cancel := context.WithTimeout(groupCtx, cfg.QueryTimeout)
			defer cancel()

			conn, err := pool.Acquire(acquireCtx)
			if err != nil {
				return fmt.Errorf("acquire connection %d: %w", index, err)
			}

			if _, err := conn.Exec(acquireCtx, "SELECT 1"); err != nil {
				conn.Release()
				return fmt.Errorf("warmup probe %d: %w", index, err)
			}

			heldMu.Lock()
			heldConns = append(heldConns, conn)
			heldMu.Unlock()
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		for _, conn := range heldConns {
			conn.Release()
		}
		return err
	}

	cfg.Logger.Printf("holding %d connections; starting keep-alives every %s", len(heldConns), cfg.KeepAlive)

	keepaliveCtx, keepaliveCancel := context.WithCancel(ctx)
	var keepaliveWG sync.WaitGroup

	for i, conn := range heldConns {
		keepaliveWG.Add(1)
		go func(id int, c *pgxpool.Conn) {
			defer keepaliveWG.Done()
			ticker := time.NewTicker(cfg.KeepAlive)
			defer ticker.Stop()

			for {
				select {
				case <-keepaliveCtx.Done():
					return
				case <-ticker.C:
					kaCtx, cancel := context.WithTimeout(ctx, cfg.QueryTimeout)
					if _, err := c.Exec(kaCtx, "SELECT 1"); err != nil {
						cfg.Logger.Printf("keepalive connection %d failed: %v", id, err)
					}
					cancel()
				}
			}
		}(i, conn)
	}

	waitCh := make(chan struct{})
	go func() {
		defer close(waitCh)
		select {
		case <-ctx.Done():
		case <-cfg.ShutdownSignal:
		}
	}()

	<-waitCh
	keepaliveCancel()
	keepaliveWG.Wait()

	for _, conn := range heldConns {
		conn.Release()
	}

	cfg.Logger.Printf("warmup shutdown complete")
	return nil
}

// RunBenchmark executes the transactional workload and emits Prometheus metrics.
func RunBenchmark(ctx context.Context, cfg RunConfig) error {
	if err := validateRunConfig(cfg); err != nil {
		return err
	}

	buckets, err := parseBuckets(cfg.HistogramConfig)
	if err != nil {
		return fmt.Errorf("parse histogram buckets: %w", err)
	}

	metrics, err := newBenchMetrics(cfg.Registry, buckets)
	if err != nil {
		return err
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return fmt.Errorf("parse dsn: %w", err)
	}

	maxConns := cfg.MaxConnections
	if maxConns <= 0 {
		maxConns = cfg.Workers * 2
	}

	poolCfg.MaxConns = int32(maxConns)
	if min := int32(cfg.Workers); min < poolCfg.MaxConns {
		poolCfg.MinConns = min
	} else {
		poolCfg.MinConns = poolCfg.MaxConns
	}
	poolCfg.HealthCheckPeriod = 30 * time.Second
	poolCfg.MaxConnIdleTime = time.Minute
	poolCfg.ConnConfig.ConnectTimeout = cfg.QueryTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create pool: %w", err)
	}
	defer pool.Close()

	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	cfg.Logger.Printf("starting benchmark: tps=%.0f workers=%d duration=%s maxConns=%d",
		cfg.TargetTPS, cfg.Workers, cfg.Duration, maxConns)

	var (
		successCount atomic.Uint64
		failureCount atomic.Uint64
		orderSeq     atomic.Uint64
	)

	limiter := rate.NewLimiter(rate.Limit(cfg.TargetTPS), cfg.Workers)
	var wg sync.WaitGroup

	for i := 0; i < cfg.Workers; i++ {
		workerID := i
		rng := rand.New(rand.NewSource(cfg.RandSeed + int64(workerID) + 1))

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := limiter.Wait(runCtx); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return
					}
					cfg.Logger.Printf("limiter error: %v", err)
					return
				}

				select {
				case <-runCtx.Done():
					return
				default:
				}

				orderID := orderSeq.Add(1)
				txCtx, cancel := context.WithTimeout(runCtx, cfg.QueryTimeout)
				start := time.Now()
				err := executeOrderTx(txCtx, pool, orderID, rng)
				cancel()

				latency := time.Since(start).Seconds()

				if err != nil {
					failureCount.Add(1)
					metrics.txFailures.Inc()
					metrics.txLatency.Observe(latency)
					if shouldLogFailure(orderID) {
						cfg.Logger.Printf("worker %d order %d error: %v", workerID, orderID, err)
					}
					continue
				}

				successCount.Add(1)
				metrics.txTotal.Inc()
				metrics.txLatency.Observe(latency)
			}
		}()
	}

	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-progressTicker.C:
				s := successCount.Load()
				f := failureCount.Load()
				cfg.Logger.Printf("progress: success=%d failure=%d", s, f)
			case <-runCtx.Done():
				return
			}
		}
	}()

	wg.Wait()
	<-done

	s := successCount.Load()
	f := failureCount.Load()
	actualTPS := float64(s) / cfg.Duration.Seconds()
	cfg.Logger.Printf("benchmark complete: success=%d failure=%d achievedTPS=%.0f", s, f, actualTPS)

	if err := runCtx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	return nil
}

const (
	accountSpace   = 10_000_000
	instrumentSpan = 100_000
)

const (
	insertOrderSQL = `
INSERT INTO core.orders (
  order_id,
  account_id,
  instrument_id,
  status,
  qty_requested,
  qty_filled,
  bonus_bucket
) VALUES ($1, $2, $3, $4, $5, 0, 0);`

	finalizeOrderSQL = `
UPDATE core.orders
SET status = $1,
    qty_filled = $2,
    bonus_bucket = $3,
    updated_at = now()
WHERE order_id = $4;`

	reserveBalanceSQL = `
UPDATE core.balances
SET available = available - $2,
    reserved = reserved + $2,
    updated_at = now()
WHERE account_id = $1
  AND available >= $2;`

	applyFillSQL = `
UPDATE core.balances
SET reserved = reserved - $2,
    exposure = exposure + $3,
    updated_at = now()
WHERE account_id = $1
  AND reserved >= $2;`

	upsertPositionSQL = `
INSERT INTO core.positions (
  account_id,
  instrument_id,
  net_qty,
  entry_value,
  updated_at
) VALUES ($1, $2, $3, $4, now())
ON CONFLICT (account_id, instrument_id) DO UPDATE
SET net_qty = core.positions.net_qty + EXCLUDED.net_qty,
    entry_value = core.positions.entry_value + EXCLUDED.entry_value,
    updated_at = now();`
)

func executeOrderTx(ctx context.Context, pool *pgxpool.Pool, orderID uint64, rng *rand.Rand) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire: %w", err)
	}
	defer conn.Release()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	if err := performOrder(ctx, tx, orderID, rng); err != nil {
		if rbErr := tx.Rollback(context.Background()); rbErr != nil {
			return fmt.Errorf("rollback after error (%v): %w", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	return nil
}

func performOrder(ctx context.Context, tx pgx.Tx, orderID uint64, rng *rand.Rand) error {
	accountID := rng.Int63n(accountSpace) + 1
	instrumentID := rng.Int63n(instrumentSpan) + 1
	qtyRequested := rng.Float64()*900 + 100 // between 100 and 1000
	price := rng.Float64()*90 + 10          // between 10 and 100
	bonus := qtyRequested * 0.001 * rng.Float64()
	fillRatio := rng.Float64()*0.5 + 0.5 // between 0.5 and 1.0
	qtyFilled := qtyRequested * fillRatio
	exposureDelta := qtyFilled * price

	if _, err := tx.Exec(ctx, insertOrderSQL,
		orderID, accountID, instrumentID, "pending", qtyRequested); err != nil {
		return fmt.Errorf("insert order: %w", err)
	}

	if tag, err := tx.Exec(ctx, reserveBalanceSQL, accountID, qtyRequested); err != nil {
		return fmt.Errorf("reserve balance: %w", err)
	} else if tag.RowsAffected() == 0 {
		return fmt.Errorf("reserve balance: insufficient funds for account %d", accountID)
	}

	if _, err := tx.Exec(ctx, upsertPositionSQL,
		accountID, instrumentID, qtyFilled, qtyFilled*price); err != nil {
		return fmt.Errorf("upsert position: %w", err)
	}

	if tag, err := tx.Exec(ctx, applyFillSQL, accountID, qtyFilled, exposureDelta); err != nil {
		return fmt.Errorf("apply fill: %w", err)
	} else if tag.RowsAffected() == 0 {
		return fmt.Errorf("apply fill: reserved deficit for account %d", accountID)
	}

	if _, err := tx.Exec(ctx, finalizeOrderSQL,
		"accepted", qtyFilled, bonus, orderID); err != nil {
		return fmt.Errorf("finalize order: %w", err)
	}

	return nil
}

func shouldLogFailure(orderID uint64) bool {
	if orderID <= 10 {
		return true
	}
	return orderID%1000 == 0
}

type benchMetrics struct {
	txTotal    prometheus.Counter
	txFailures prometheus.Counter
	txLatency  prometheus.Observer
}

func newBenchMetrics(reg *prometheus.Registry, buckets []float64) (*benchMetrics, error) {
	if reg == nil {
		return nil, errors.New("prometheus registry is required")
	}

	txTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omsbench_tx_total",
		Help: "Total committed transactions.",
	})
	txFailures := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "omsbench_tx_fail_total",
		Help: "Total failed transactions.",
	})
	txLatency := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "omsbench_tx_seconds",
		Help:    "Histogram of transaction latencies.",
		Buckets: buckets,
	})

	if err := reg.Register(txTotal); err != nil {
		return nil, fmt.Errorf("register tx_total: %w", err)
	}
	if err := reg.Register(txFailures); err != nil {
		return nil, fmt.Errorf("register tx_fail_total: %w", err)
	}
	if err := reg.Register(txLatency); err != nil {
		return nil, fmt.Errorf("register tx_seconds: %w", err)
	}

	return &benchMetrics{
		txTotal:    txTotal,
		txFailures: txFailures,
		txLatency:  txLatency,
	}, nil
}

func validateWarmupConfig(cfg WarmupConfig) error {
	if strings.TrimSpace(cfg.DSN) == "" {
		return fmt.Errorf("%w: DSN is required", ErrInvalidConfig)
	}
	if cfg.Connections <= 0 {
		return fmt.Errorf("%w: connections must be positive", ErrInvalidConfig)
	}
	if cfg.Parallelism <= 0 {
		return fmt.Errorf("%w: parallelism must be positive", ErrInvalidConfig)
	}
	if cfg.KeepAlive <= 0 {
		return fmt.Errorf("%w: keepalive must be positive", ErrInvalidConfig)
	}
	if cfg.QueryTimeout <= 0 {
		return fmt.Errorf("%w: query timeout must be positive", ErrInvalidConfig)
	}
	if cfg.Logger == nil {
		return fmt.Errorf("%w: logger is required", ErrInvalidConfig)
	}
	return nil
}

func validateRunConfig(cfg RunConfig) error {
	if strings.TrimSpace(cfg.DSN) == "" {
		return fmt.Errorf("%w: DSN is required", ErrInvalidConfig)
	}
	if cfg.TargetTPS <= 0 {
		return fmt.Errorf("%w: target TPS must be positive", ErrInvalidConfig)
	}
	if cfg.Workers <= 0 {
		return fmt.Errorf("%w: workers must be positive", ErrInvalidConfig)
	}
	if cfg.Duration <= 0 {
		return fmt.Errorf("%w: duration must be positive", ErrInvalidConfig)
	}
	if cfg.QueryTimeout <= 0 {
		return fmt.Errorf("%w: query timeout must be positive", ErrInvalidConfig)
	}
	if cfg.Logger == nil {
		return fmt.Errorf("%w: logger is required", ErrInvalidConfig)
	}
	if cfg.Registry == nil {
		return fmt.Errorf("%w: prometheus registry is required", ErrInvalidConfig)
	}
	return nil
}

func parseBuckets(raw string) ([]float64, error) {
	parts := strings.Split(raw, ",")
	buckets := make([]float64, 0, len(parts))
	prev := -math.MaxFloat64
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return nil, fmt.Errorf("bucket %q: %w", part, err)
		}
		if v <= 0 {
			return nil, fmt.Errorf("bucket %q must be > 0", part)
		}
		if v <= prev {
			return nil, errors.New("histogram buckets must be strictly increasing")
		}
		prev = v
		buckets = append(buckets, v)
	}
	if len(buckets) == 0 {
		return nil, errors.New("no histogram buckets parsed")
	}
	return buckets, nil
}
