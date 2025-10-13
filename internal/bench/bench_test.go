package bench

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"
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
	tests := []string{
		"",
		"0.02,0.01",
		"a,b",
	}
	for _, tc := range tests {
		if _, err := parseBuckets(tc); err == nil {
			t.Fatalf("expected error for %q", tc)
		}
	}
}

func TestValidateWarmupConfig(t *testing.T) {
	valid := WarmupConfig{
		DSN:            "postgres://user:pass@localhost/db",
		Connections:    10,
		Parallelism:    2,
		MaxConnectRate: 50,
		KeepAlive:      time.Second,
		QueryTimeout:   time.Second,
		Logger:         testLogger{t},
	}
	if err := validateWarmupConfig(valid); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	invalid := valid
	invalid.DSN = ""
	if err := validateWarmupConfig(invalid); err == nil {
		t.Fatalf("expected error for missing DSN")
	}
}

func TestValidateRunConfig(t *testing.T) {
	valid := RunConfig{
		DSN:             "postgres://user:pass@localhost/db",
		TargetTPS:       1,
		Workers:         1,
		Duration:        time.Second,
		HistogramConfig: "0.01,0.1",
		QueryTimeout:    time.Second,
		Logger:          testLogger{t},
		Registry:        NewRegistry(),
	}
	if err := validateRunConfig(valid); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	invalid := valid
	invalid.Workers = 0
	if err := validateRunConfig(invalid); err == nil {
		t.Fatalf("expected error for workers")
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

func TestPerformOrder(t *testing.T) {
	mockPool, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock: %v", err)
	}
	defer mockPool.Close()

	mockPool.ExpectBegin()
	mockPool.ExpectExec(`INSERT INTO core\.orders`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), "pending", pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mockPool.ExpectExec(`UPDATE core\.balances`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mockPool.ExpectExec(`INSERT INTO core\.positions`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))
	mockPool.ExpectExec(`UPDATE core\.balances`).
		WithArgs(pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mockPool.ExpectExec(`UPDATE core\.orders`).
		WithArgs("accepted", pgxmock.AnyArg(), pgxmock.AnyArg(), pgxmock.AnyArg()).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))
	mockPool.ExpectRollback()

	ctx := context.Background()
	tx, err := mockPool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}

	rng := rand.New(rand.NewSource(123))
	if err := performOrder(ctx, tx, 42, rng); err != nil {
		t.Fatalf("performOrder: %v", err)
	}

	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	if err := mockPool.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

type testLogger struct {
	t *testing.T
}

func (l testLogger) Printf(format string, args ...any) {
	l.t.Helper()
}
