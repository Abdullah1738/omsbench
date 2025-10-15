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

	fdb "github.com/apple/foundationdb/bindings/go/src/fdb"
	"github.com/apple/foundationdb/bindings/go/src/fdb/tuple"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/time/rate"
)

// DefaultAPIVersion is the FoundationDB API version this benchmark targets.
// FoundationDB 7.3 clients negotiate API version 730.
const DefaultAPIVersion = 730

const (
	accountSpace             = 10_000_000
	instrumentSpan           = 1_000
	initialAccountLiquidity  = 1_000_000_000 // synthetic baseline to avoid reserve starvation
	progressLogInterval      = 10 * time.Second
	defaultDirectoryFragment = "omsbench"
)

var (
	apiVersionOnce       sync.Once
	negotiatedAPIVersion int
)

// RunConfig configures the benchmark workload.
type RunConfig struct {
	ClusterFile     string
	DirectoryPath   []string
	APIVersion      int
	TargetTPS       float64
	Workers         int
	Duration        time.Duration
	HistogramConfig string
	TxTimeout       time.Duration
	Logger          Logger
	RandSeed        int64
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

	apiVersion := cfg.APIVersion
	if apiVersion <= 0 {
		apiVersion = DefaultAPIVersion
	}
	apiVersionOnce.Do(func() {
		fdb.MustAPIVersion(apiVersion)
		negotiatedAPIVersion = apiVersion
	})
	if negotiatedAPIVersion != 0 && negotiatedAPIVersion != apiVersion {
		cfg.Logger.Printf("ignoring api-version=%d; already negotiated %d", apiVersion, negotiatedAPIVersion)
	}

	db := fdb.MustOpenDatabase(cfg.ClusterFile)

	namespace := normalizeDirectory(cfg.DirectoryPath)

	runCtx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	cfg.Logger.Printf("starting FoundationDB benchmark: tps=%.0f workers=%d duration=%s namespace=%s",
		cfg.TargetTPS, cfg.Workers, cfg.Duration, strings.Join(namespace, "/"))

	var (
		successCount atomic.Uint64
		failureCount atomic.Uint64
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

				orderID := uint64(rng.Int63())
				params := randomOrderParams(orderID, rng)

				latency, err := executeOrderTx(runCtx, db, namespace, params, cfg.TxTimeout)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return
					}
					failureCount.Add(1)
					metrics.txFailures.Inc()
					metrics.txLatency.Observe(latency.Seconds())
					if shouldLogFailure(orderID) {
						cfg.Logger.Printf("worker %d order %d error: %v", workerID, orderID, err)
					}
					continue
				}

				successCount.Add(1)
				metrics.txTotal.Inc()
				metrics.txLatency.Observe(latency.Seconds())
			}
		}()
	}

	progressTicker := time.NewTicker(progressLogInterval)
	defer progressTicker.Stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-progressTicker.C:
				cfg.Logger.Printf("progress: success=%d failure=%d",
					successCount.Load(), failureCount.Load())
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

	if quantiles, err := gatherLatencyQuantiles(cfg.Registry, "omsbench_tx_seconds", []float64{0.10, 0.50, 0.99}); err != nil {
		cfg.Logger.Printf("latency quantiles unavailable: %v", err)
	} else if len(quantiles) > 0 {
		cfg.Logger.Printf("latency quantiles: p10=%.2fms p50=%.2fms p99=%.2fms",
			quantiles[0.10]*1000,
			quantiles[0.50]*1000,
			quantiles[0.99]*1000,
		)
	}

	if err := runCtx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}

	return nil
}

type orderParams struct {
	orderID       uint64
	accountID     int64
	instrumentID  int64
	qtyRequested  float64
	price         float64
	bonus         float64
	qtyFilled     float64
	exposureDelta float64
}

func randomOrderParams(orderID uint64, rng *rand.Rand) orderParams {
	qtyRequested := rng.Float64()*900 + 100 // between 100 and 1000
	price := rng.Float64()*90 + 10          // between 10 and 100
	bonus := qtyRequested * 0.001 * rng.Float64()
	fillRatio := rng.Float64()*0.5 + 0.5 // between 0.5 and 1.0
	qtyFilled := qtyRequested * fillRatio
	exposureDelta := qtyFilled * price

	return orderParams{
		orderID:       orderID,
		accountID:     rng.Int63n(accountSpace) + 1,
		instrumentID:  rng.Int63n(instrumentSpan) + 1,
		qtyRequested:  qtyRequested,
		price:         price,
		bonus:         bonus,
		qtyFilled:     qtyFilled,
		exposureDelta: exposureDelta,
	}
}

func executeOrderTx(ctx context.Context, db fdb.Database, namespace []string, params orderParams, txTimeout time.Duration) (time.Duration, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	start := time.Now()
	_, err := db.Transact(func(tr fdb.Transaction) (any, error) {
		if txTimeout > 0 {
			timeoutMS := txTimeout / time.Millisecond
			if timeoutMS <= 0 {
				timeoutMS = 1
			}
			tr.Options().SetTimeout(int64(timeoutMS))
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := performOrder(tr, namespace, params); err != nil {
			return nil, err
		}

		return nil, nil
	})
	latency := time.Since(start)

	if err != nil {
		return latency, err
	}

	select {
	case <-ctx.Done():
		return latency, ctx.Err()
	default:
		return latency, nil
	}
}

func performOrder(tr fdb.Transaction, namespace []string, params orderParams) error {
	now := time.Now().UnixNano()

	orderKey := packOrderKey(namespace, params.orderID)
	balanceKey := packBalanceKey(namespace, params.accountID)
	positionKey := packPositionKey(namespace, params.accountID, params.instrumentID)

	balance, err := loadBalance(tr, balanceKey)
	if err != nil {
		return fmt.Errorf("load balance: %w", err)
	}

	if balance.Available < params.qtyRequested {
		return fmt.Errorf("reserve balance: insufficient funds for account %d", params.accountID)
	}

	balance.Available -= params.qtyRequested
	balance.Reserved += params.qtyRequested

	if balance.Reserved < params.qtyFilled {
		return fmt.Errorf("apply fill: reserved deficit for account %d", params.accountID)
	}

	balance.Reserved -= params.qtyFilled
	balance.Exposure += params.exposureDelta
	balance.UpdatedAt = now

	position, err := loadPosition(tr, positionKey)
	if err != nil {
		return fmt.Errorf("load position: %w", err)
	}

	position.NetQty += params.qtyFilled
	position.EntryValue += params.qtyFilled * params.price
	position.UpdatedAt = now

	order := orderRecord{
		AccountID:    params.accountID,
		InstrumentID: params.instrumentID,
		Status:       "accepted",
		QtyRequested: params.qtyRequested,
		QtyFilled:    params.qtyFilled,
		Bonus:        params.bonus,
		UpdatedAt:    now,
	}

	tr.Set(orderKey, order.pack())
	tr.Set(balanceKey, balance.pack())
	tr.Set(positionKey, position.pack())

	return nil
}

func packOrderKey(namespace []string, orderID uint64) fdb.Key {
	key := tuple.Tuple{"order", orderID}
	if len(namespace) > 0 {
		ns := make(tuple.Tuple, 0, len(namespace)+2)
		for _, part := range namespace {
			ns = append(ns, part)
		}
		ns = append(ns, key...)
		return fdb.Key(ns.Pack())
	}
	return fdb.Key(key.Pack())
}

func packBalanceKey(namespace []string, accountID int64) fdb.Key {
	key := tuple.Tuple{"balance", accountID}
	if len(namespace) > 0 {
		ns := make(tuple.Tuple, 0, len(namespace)+2)
		for _, part := range namespace {
			ns = append(ns, part)
		}
		ns = append(ns, key...)
		return fdb.Key(ns.Pack())
	}
	return fdb.Key(key.Pack())
}

func packPositionKey(namespace []string, accountID int64, instrumentID int64) fdb.Key {
	key := tuple.Tuple{"position", accountID, instrumentID}
	if len(namespace) > 0 {
		ns := make(tuple.Tuple, 0, len(namespace)+3)
		for _, part := range namespace {
			ns = append(ns, part)
		}
		ns = append(ns, key...)
		return fdb.Key(ns.Pack())
	}
	return fdb.Key(key.Pack())
}

type balanceRecord struct {
	Available float64
	Reserved  float64
	Exposure  float64
	UpdatedAt int64
}

func (b balanceRecord) pack() []byte {
	return tuple.Tuple{
		b.Available,
		b.Reserved,
		b.Exposure,
		b.UpdatedAt,
	}.Pack()
}

func loadBalance(tr fdb.Transaction, key fdb.Key) (balanceRecord, error) {
	raw := tr.Get(key).MustGet()
	if len(raw) == 0 {
		return balanceRecord{
			Available: initialAccountLiquidity,
			Reserved:  0,
			Exposure:  0,
			UpdatedAt: 0,
		}, nil
	}

	t, err := tuple.Unpack(raw)
	if err != nil {
		return balanceRecord{}, err
	}
	if len(t) != 4 {
		return balanceRecord{}, fmt.Errorf("unexpected balance tuple length %d", len(t))
	}
	available, err := tupleFloat64(t[0])
	if err != nil {
		return balanceRecord{}, err
	}
	reserved, err := tupleFloat64(t[1])
	if err != nil {
		return balanceRecord{}, err
	}
	exposure, err := tupleFloat64(t[2])
	if err != nil {
		return balanceRecord{}, err
	}
	updatedAt, err := tupleInt64(t[3])
	if err != nil {
		return balanceRecord{}, err
	}

	return balanceRecord{
		Available: available,
		Reserved:  reserved,
		Exposure:  exposure,
		UpdatedAt: updatedAt,
	}, nil
}

type positionRecord struct {
	NetQty     float64
	EntryValue float64
	UpdatedAt  int64
}

func (p positionRecord) pack() []byte {
	return tuple.Tuple{
		p.NetQty,
		p.EntryValue,
		p.UpdatedAt,
	}.Pack()
}

func loadPosition(tr fdb.Transaction, key fdb.Key) (positionRecord, error) {
	raw := tr.Get(key).MustGet()
	if len(raw) == 0 {
		return positionRecord{}, nil
	}

	t, err := tuple.Unpack(raw)
	if err != nil {
		return positionRecord{}, err
	}
	if len(t) != 3 {
		return positionRecord{}, fmt.Errorf("unexpected position tuple length %d", len(t))
	}
	netQty, err := tupleFloat64(t[0])
	if err != nil {
		return positionRecord{}, err
	}
	entryValue, err := tupleFloat64(t[1])
	if err != nil {
		return positionRecord{}, err
	}
	updatedAt, err := tupleInt64(t[2])
	if err != nil {
		return positionRecord{}, err
	}

	return positionRecord{
		NetQty:     netQty,
		EntryValue: entryValue,
		UpdatedAt:  updatedAt,
	}, nil
}

type orderRecord struct {
	AccountID    int64
	InstrumentID int64
	Status       string
	QtyRequested float64
	QtyFilled    float64
	Bonus        float64
	UpdatedAt    int64
}

func (o orderRecord) pack() []byte {
	return tuple.Tuple{
		o.AccountID,
		o.InstrumentID,
		o.Status,
		o.QtyRequested,
		o.QtyFilled,
		o.Bonus,
		o.UpdatedAt,
	}.Pack()
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

func validateRunConfig(cfg RunConfig) error {
	if cfg.TargetTPS <= 0 {
		return fmt.Errorf("%w: target TPS must be positive", ErrInvalidConfig)
	}
	if cfg.Workers <= 0 {
		return fmt.Errorf("%w: workers must be positive", ErrInvalidConfig)
	}
	if cfg.Duration <= 0 {
		return fmt.Errorf("%w: duration must be positive", ErrInvalidConfig)
	}
	if cfg.TxTimeout <= 0 {
		return fmt.Errorf("%w: transaction timeout must be positive", ErrInvalidConfig)
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

func tupleFloat64(v any) (float64, error) {
	switch t := v.(type) {
	case float64:
		return t, nil
	case float32:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case int:
		return float64(t), nil
	default:
		return 0, fmt.Errorf("expected float-like tuple element, got %T", v)
	}
}

func tupleInt64(v any) (int64, error) {
	switch t := v.(type) {
	case int64:
		return t, nil
	case int:
		return int64(t), nil
	case float64:
		return int64(t), nil
	default:
		return 0, fmt.Errorf("expected integer-like tuple element, got %T", v)
	}
}

func normalizeDirectory(parts []string) []string {
	if len(parts) == 0 {
		return []string{defaultDirectoryFragment}
	}

	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return []string{defaultDirectoryFragment}
	}
	return out
}

func gatherLatencyQuantiles(reg *prometheus.Registry, metricName string, quantiles []float64) (map[float64]float64, error) {
	if reg == nil {
		return nil, errors.New("prometheus registry is required")
	}

	families, err := reg.Gather()
	if err != nil {
		return nil, fmt.Errorf("gather metrics: %w", err)
	}

	var histogram *dto.Histogram
	for _, fam := range families {
		if fam == nil || fam.GetName() != metricName {
			continue
		}
		for _, metric := range fam.GetMetric() {
			if metric.GetHistogram() == nil {
				continue
			}
			histogram = metric.GetHistogram()
			break
		}
		if histogram != nil {
			break
		}
	}

	if histogram == nil || histogram.GetSampleCount() == 0 {
		return map[float64]float64{}, nil
	}

	total := histogram.GetSampleCount()
	buckets := histogram.GetBucket()

	out := make(map[float64]float64, len(quantiles))
	for _, q := range quantiles {
		switch {
		case q <= 0:
			out[q] = 0
		case q >= 1:
			out[q] = histogram.GetSampleSum() / float64(total)
		default:
			out[q] = approximateHistogramQuantile(buckets, q, total)
		}
	}
	return out, nil
}

func approximateHistogramQuantile(buckets []*dto.Bucket, quantile float64, total uint64) float64 {
	if len(buckets) == 0 || total == 0 {
		return 0
	}

	target := quantile * float64(total)
	if target <= 1 {
		target = 1
	}

	var (
		prevUpper float64
		prevCount uint64
	)

	for _, b := range buckets {
		cumulative := b.GetCumulativeCount()
		if float64(cumulative) >= target {
			lowerBound := prevUpper
			upperBound := b.GetUpperBound()
			countInBucket := cumulative - prevCount
			if countInBucket == 0 {
				if math.IsInf(upperBound, 1) {
					return lowerBound
				}
				return upperBound
			}

			if math.IsInf(upperBound, 1) {
				return lowerBound
			}

			fraction := (target - float64(prevCount)) / float64(countInBucket)
			if fraction < 0 {
				fraction = 0
			} else if fraction > 1 {
				fraction = 1
			}
			return lowerBound + fraction*(upperBound-lowerBound)
		}

		prevUpper = b.GetUpperBound()
		prevCount = cumulative
	}

	return prevUpper
}
