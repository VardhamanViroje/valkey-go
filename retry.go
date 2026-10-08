package valkey

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go/internal/util"
)

const (
	defaultMaxRetries    = 20
	defaultMaxRetryDelay = 1 * time.Second
)

// RetryDelayFn returns the delay that should be used before retrying the
// attempt. Will return a negative delay if the delay could not be determined or does not retry.
type RetryDelayFn func(attempts int, cmd Completed, err error) time.Duration

func isAdaptiveRetryError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNoSlot) {
		return true
	}
	if isPreFlightDialError(err) {
		return true
	}
	var pf *errPreFlight
	if errors.As(err, &pf) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var vErr *ValkeyError
	if errors.As(err, &vErr) {
		return vErr.IsClusterDown() || vErr.IsTryAgain() || vErr.IsLoading()
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "clusterdown") ||
		strings.Contains(msg, "tryagain") ||
		strings.Contains(msg, "loading") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "no route to host") ||
		strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "eof")
}

// defaultRetryDelayFn delays the next retry exponentially.
// For network dial errors, socket disconnections, cluster transitions (CLUSTERDOWN),
// and unassigned slots (ErrNoSlot), it adaptively scales backoff in milliseconds (up to 1s)
// to provide a resilient failover convergence window. For standard errors, it uses microseconds.
func defaultRetryDelayFn(attempts int, _ Completed, err error) time.Duration {
	if isAdaptiveRetryError(err) {
		base := 10 * (1 << min(7, attempts))
		jitter := util.FastRand(base)
		return min(defaultMaxRetryDelay, time.Duration(base+jitter)*time.Millisecond)
	}
	base := 1 << min(defaultMaxRetries, attempts)
	jitter := util.FastRand(base)
	return min(defaultMaxRetryDelay, time.Duration(base+jitter)*time.Microsecond)
}

type retryHandler interface {
	// RetryDelay returns the delay that should be used before retrying the
	// attempt. Will return a negative delay if the delay could not be determined or does
	// not retry.
	// If the delay is zero, the next retry should be attempted immediately.
	RetryDelay(attempts int, cmd Completed, err error) time.Duration

	// WaitForRetry waits until the next retry should be attempted.
	WaitForRetry(ctx context.Context, duration time.Duration)

	// WaitOrSkipRetry waits until the next retry should be attempted
	// or returns false if the command should not be retried.
	// Returns false immediately if the command should not be retried.
	// Returns true after the delay if the command should be retried.
	WaitOrSkipRetry(ctx context.Context, attempts int, cmd Completed, err error) bool
}

type retryer struct {
	RetryDelayFn RetryDelayFn
}

var _ retryHandler = (*retryer)(nil)

func newRetryer(retryDelayFn RetryDelayFn) *retryer {
	return &retryer{RetryDelayFn: retryDelayFn}
}

func (r *retryer) RetryDelay(attempts int, cmd Completed, err error) time.Duration {
	return r.RetryDelayFn(attempts, cmd, err)
}

func (r *retryer) WaitForRetry(ctx context.Context, duration time.Duration) {
	if duration > 0 {
		if ch := ctx.Done(); ch != nil {
			tm := time.NewTimer(duration)
			defer tm.Stop()
			select {
			case <-ch:
			case <-tm.C:
			}
		} else {
			time.Sleep(duration)
		}
	}
}

func (r *retryer) WaitOrSkipRetry(
	ctx context.Context, attempts int, cmd Completed, err error,
) bool {
	if delay := r.RetryDelay(attempts, cmd, err); delay == 0 {
		runtime.Gosched()
		return true
	} else if delay > 0 {
		if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > delay {
			r.WaitForRetry(ctx, delay)
			return true
		}
	}
	return false
}
