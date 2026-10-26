package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// connect builds the valkey client. valkey-go dials InitAddress once and returns an ERR_IAM_*
// reply to HELLO as an error without retrying, so connect retries those with the backoff
// Google recommends for IAM backend errors. ctx bounds the retries, which also stop after
// setupTimeout when ctx has no earlier deadline.
//
// wantCluster asks connect to check that valkey-go built a cluster client. valkey-go quietly
// falls back to a single-node client when CLUSTER SHARDS fails, for example because an ACL
// rule doesn't allow it, and on a cluster that client gets MOVED errors for the keys of other
// shards. user names the AUTH user in error messages ("" when unknown).
func connect(ctx context.Context, opt valkey.ClientOption, wantCluster bool, user string) (valkey.Client, error) {
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
			if wantCluster && !opt.ForceSingleClient && client.Mode() != valkey.ClientModeCluster {
				return nil, notClusterError(ctx, client, opt.InitAddress, user)
			}
			return client, nil
		}
		if !isIAMBackendError(err) {
			return nil, explainHandshakeError(err, user)
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

// explainHandshakeError adds a hint when an ACL rule refused CLIENT TRACKING, which
// valkey-go sends on every new connection unless ClientOption.DisableCache is set.
func explainHandshakeError(err error, user string) error {
	if errors.Is(err, valkey.ErrNoCache) && strings.Contains(err.Error(), "NOPERM") {
		return fmt.Errorf("valkeygcp: the ACL rule for %s must allow CLIENT TRACKING (+client|tracking), or set ClientOption.DisableCache: %w", who(user), err)
	}
	return err
}

// notClusterError closes a single-node client that valkey-go built for a cluster-mode
// endpoint, and returns an error that explains why, using the error CLUSTER SHARDS returns
// now.
func notClusterError(ctx context.Context, client valkey.Client, init []string, user string) error {
	defer client.Close()
	why := "CLUSTER SHARDS failed during setup"
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := client.Do(probeCtx, client.B().ClusterShards().Build()).Error(); err != nil {
		why = "CLUSTER SHARDS: " + err.Error()
	}
	return fmt.Errorf("valkeygcp: %s is a cluster-mode endpoint, but valkey-go fell back to a single-node client (%s); if an ACL policy applies, the rule for %s must allow +cluster|shards",
		strings.Join(init, ","), why, who(user))
}

// who names the AUTH user in error messages.
func who(user string) string {
	if user == "" {
		return "the connecting user"
	}
	return fmt.Sprintf("user %q", user)
}
