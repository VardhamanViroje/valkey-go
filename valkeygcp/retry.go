package valkeygcp

import (
	"math/rand/v2"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

const (
	retryBase        = 50 * time.Millisecond
	retryCap         = 2 * time.Second
	iamBackoffBase   = 250 * time.Millisecond
	iamBackoffCap    = 10 * time.Second
	maxRetryAttempts = 20
)

// memorystoreRetryDelay is exponential backoff with full jitter. Memorystore IAM backend
// errors (ERR_IAM_EXHAUSTED / ERR_IAM_OTHER) back off longer, as Google advises.
// It is a valkey.RetryDelayFn: negative stops retrying, 0 retries now, positive waits.
func memorystoreRetryDelay(attempts int, _ valkey.Completed, err error) time.Duration {
	if attempts >= maxRetryAttempts {
		return -1
	}
	base, limit := retryBase, retryCap
	if err != nil {
		if msg := err.Error(); strings.Contains(msg, "ERR_IAM_EXHAUSTED") || strings.Contains(msg, "ERR_IAM_OTHER") {
			base, limit = iamBackoffBase, iamBackoffCap
		}
	}
	backoff := base << min(max(attempts, 0), 16)
	if backoff <= 0 || backoff > limit {
		backoff = limit
	}
	return time.Duration(rand.Int64N(int64(backoff)) + 1)
}

