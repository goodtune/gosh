//go:build !windows

package client

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// WatchResize delivers a tick whenever the terminal size may have changed,
// via SIGWINCH. The watcher stops when ctx is cancelled.
func WatchResize(ctx context.Context) <-chan struct{} {
	out := make(chan struct{}, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	go func() {
		defer signal.Stop(sig)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}
