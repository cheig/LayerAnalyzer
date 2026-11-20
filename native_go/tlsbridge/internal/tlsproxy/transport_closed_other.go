//go:build !windows

package tlsproxy

import (
	"errors"
	"syscall"
)

func isConnectionClosed(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}
