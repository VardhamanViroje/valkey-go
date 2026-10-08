package valkey

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type mockRetryHandler struct {
	RetryDelayFn        func(attempts int, _ Completed, err error) time.Duration
	WaitForRetryFn      func(ctx context.Context, duration time.Duration)
	WaitOrSkipRetryFunc func(ctx context.Context, attempts int, _ Completed, err error) bool
}

var _ retryHandler = (*mockRetryHandler)(nil)

func (m *mockRetryHandler) WaitOrSkipRetry(ctx context.Context, attempts int, cmd Completed, err error) bool {
	return m.WaitOrSkipRetryFunc(ctx, attempts, cmd, err)
}

func (m *mockRetryHandler) RetryDelay(attempts int, cmd Completed, err error) time.Duration {
	return m.RetryDelayFn(attempts, cmd, err)
}

func (m *mockRetryHandler) WaitForRetry(ctx context.Context, duration time.Duration) {
	m.WaitForRetryFn(ctx, duration)
}

func TestDefaultRetryDelay(t *testing.T) {
	for i := range 100 {
		err := errors.New("test")
		got := defaultRetryDelayFn(i, Completed{}, err)

		if got < 0 || got > defaultMaxRetryDelay {
			t.Errorf("defaultRetryDelayFn(%d, %v) = %v; want >= 0 and <= %v", i, err, got, defaultMaxRetryDelay)
		}
	}
}

func TestAdaptiveRetryDelay(t *testing.T) {
	adaptiveErrs := []error{
		ErrNoSlot,
		&net.OpError{Op: "dial", Err: errors.New("connection refused")},
		&errPreFlight{error: errors.New("dial failed")},
		errors.New("CLUSTERDOWN Hash slot not served"),
		errors.New("TRYAGAIN Multiple keys request"),
		errors.New("LOADING Valkey is loading dataset"),
		errors.New("connection refused"),
		errors.New("EOF"),
		errors.New("read: connection reset by peer"),
	}

	for _, err := range adaptiveErrs {
		for i := 0; i < 20; i++ {
			delay := defaultRetryDelayFn(i, Completed{}, err)
			if delay < 10*time.Millisecond {
				t.Errorf("expected adaptive delay >= 10ms for %v at attempt %d, got %v", err, i, delay)
			}
			if delay > defaultMaxRetryDelay {
				t.Errorf("delay %v exceeded cap %v for %v", delay, defaultMaxRetryDelay, err)
			}
		}
	}

	normalErr := errors.New("normal error")
	delay0 := defaultRetryDelayFn(0, Completed{}, normalErr)
	if delay0 >= 10*time.Millisecond {
		t.Errorf("expected microsecond delay for normal error, got %v", delay0)
	}
}

func TestRetryer_RetryDelay(t *testing.T) {
	r := &retryer{
		RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
			return time.Second
		},
	}

	got := r.RetryDelay(0, Completed{}, nil)
	if got != time.Second {
		t.Errorf("RetryDelay() = %v; want %v", got, time.Second)
	}
}

func TestRetryer_WaitForRetry(t *testing.T) {
	t.Run("context is canceled", func(t *testing.T) {
		r := &retryer{}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		r.WaitForRetry(ctx, time.Second)
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitForRetry() took %v; want < 100ms", elapsed)
		}
	})

	t.Run("context deadline is before duration", func(t *testing.T) {
		r := &retryer{}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		r.WaitForRetry(ctx, time.Second)
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitForRetry() took %v; want < 100ms", elapsed)
		}
	})

	t.Run("wait until duration", func(t *testing.T) {
		r := &retryer{}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		start := time.Now()
		r.WaitForRetry(ctx, 50*time.Millisecond)
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitForRetry() took %v; want < 100ms", elapsed)
		}
	})

	t.Run("empty context", func(t *testing.T) {
		r := &retryer{}

		start := time.Now()
		r.WaitForRetry(context.Background(), 50*time.Millisecond)
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitForRetry() took %v; want < 100ms", elapsed)
		}
	})
}

func TestRetrier_WaitOrSkipRetry(t *testing.T) {
	t.Run("RetryDelayFn returns negative delay", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return -1 * time.Second
			},
		}

		shouldRetry := r.WaitOrSkipRetry(nil, 0, Completed{}, nil)
		if shouldRetry {
			t.Error("WaitOrSkipRetry() = true; want false")
		}
	})

	t.Run("RetryDelayFn returns 0 delay", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return 0
			},
		}

		shouldRetry := r.WaitOrSkipRetry(nil, 0, Completed{}, nil)
		if !shouldRetry {
			t.Error("WaitOrSkipRetry() = false; want true")
		}
	})

	t.Run("context is canceled", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return time.Second
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		shouldRetry := r.WaitOrSkipRetry(ctx, 0, Completed{}, nil)
		if !shouldRetry {
			t.Error("WaitOrSkipRetry() = false; want true")
		}
	})

	t.Run("context deadline is before delay", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return time.Second
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		start := time.Now()
		shouldRetry := r.WaitOrSkipRetry(ctx, 0, Completed{}, nil)
		if shouldRetry {
			t.Error("WaitOrSkipRetry() = true; want false")
		}
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitOrSkipRetry() took %v; want < 100ms", elapsed)
		}
	})

	t.Run("wait until next retry", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return 50 * time.Millisecond
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		start := time.Now()
		shouldRetry := r.WaitOrSkipRetry(ctx, 0, Completed{}, nil)
		if !shouldRetry {
			t.Error("WaitOrSkipRetry() = false; want true")
		}
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitOrSkipRetry() took %v; want < 100ms", elapsed)
		}
	})

	t.Run("empty context", func(t *testing.T) {
		r := &retryer{
			RetryDelayFn: func(attempts int, _ Completed, err error) time.Duration {
				return 50 * time.Millisecond
			},
		}

		start := time.Now()
		shouldRetry := r.WaitOrSkipRetry(context.Background(), 0, Completed{}, nil)
		if !shouldRetry {
			t.Error("WaitOrSkipRetry() = false; want true")
		}
		elapsed := time.Since(start)

		if elapsed > 100*time.Millisecond {
			t.Errorf("WaitOrSkipRetry() took %v; want < 100ms", elapsed)
		}
	})
}
