//go:build windows

package client

import (
	"context"
	"os"
	"time"

	"github.com/goodtune/gosh/internal/termenv"
)

// WatchResize polls the console size four times a second — Windows has no
// SIGWINCH, and a 250ms poll is imperceptible next to network latency.
func WatchResize(ctx context.Context) <-chan struct{} {
	out := make(chan struct{}, 1)
	go func() {
		lastW, lastH := termenv.Size(os.Stdout)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w, h, ok := termenv.TrySize(os.Stdout)
				if !ok {
					continue // transient query failure is not a resize
				}
				if w != lastW || h != lastH {
					lastW, lastH = w, h
					select {
					case out <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return out
}
