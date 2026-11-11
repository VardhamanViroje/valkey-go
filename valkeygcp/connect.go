package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// connect builds the valkey client. valkey-go dials each InitAddress once and returns an
// ERR_IAM_* reply to HELLO as an error without retrying, so connect retries those with
// exponential backoff, as Google recommends for these errors. ctx bounds the retries, which
// also stop after setupTimeout when ctx has no earlier deadline.
func connect(ctx context.Context, opt valkey.ClientOption) (valkey.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				return nil, err // valkey.NewClient takes no context
			}
			return nil, fmt.Errorf("valkeygcp: %w (gave up after %d attempts: %w)", lastErr, attempt, err)
		}
		client, err := valkey.NewClient(opt)
		if err == nil {
			return client, nil
		}
		if !isIAMBackendError(err) {
			return nil, explainHandshakeError(err, opt.SelectDB)
		}
		lastErr = err
		t := time.NewTimer(iamBackoff(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}

// selectDBRefusals are the replies of an instance that has no database ClientOption.SelectDB,
// which valkey-go selects with SELECT on every new connection. valkey-go drops their "ERR ".
var selectDBRefusals = []string{
	"SELECT is not allowed in cluster mode", // Cluster Mode Enabled, before Valkey 9.0
	"DB index is out of range",              // no such database
}

// explainHandshakeError adds a hint to two handshake errors:
//   - An ACL rule refused CLIENT TRACKING, which valkey-go sends on every new connection
//     unless ClientOption.DisableCache is set. The hint names no user: Memorystore matches
//     ACL rules to the IAM principal that authenticated, which isn't the AUTH username
//     "default", and its NOPERM reply, kept in the error, names the rule's user.
//   - The instance has no database selectDB, the ClientOption.SelectDB. Its number of
//     databases is set when it is created, and valkeygcp can't tell it before connecting, so
//     only the instance's reply shows it.
func explainHandshakeError(err error, selectDB int) error {
	if msg := err.Error(); errors.Is(err, valkey.ErrNoCache) && strings.Contains(msg, "NOPERM") && strings.Contains(msg, "TRACKING") {
		return fmt.Errorf("valkeygcp: the ACL rule must allow CLIENT TRACKING (+client|tracking), or set ClientOption.DisableCache: %w", err)
	}
	if selectDB != 0 && isSelectDBRefusal(err) {
		return fmt.Errorf("valkeygcp: the instance has no database %d (ClientOption.SelectDB); an instance's number of "+
			"databases is set when it is created: databases for Cluster Mode Disabled (16 by default), "+
			"cluster-databases for Cluster Mode Enabled (Valkey 9.0 and later, 1 by default): %w", selectDB, err)
	}
	return err
}

// isSelectDBRefusal reports whether err is an instance's reply to a SELECT of a database it
// doesn't have.
func isSelectDBRefusal(err error) bool {
	var verr *valkey.ValkeyError
	if !errors.As(err, &verr) {
		return false
	}
	for _, refusal := range selectDBRefusals {
		if strings.Contains(verr.Error(), refusal) {
			return true
		}
	}
	return false
}
