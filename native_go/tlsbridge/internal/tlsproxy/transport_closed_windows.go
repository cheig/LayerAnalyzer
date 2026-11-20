package tlsproxy

import (
	"errors"
	"syscall"
)

func isConnectionClosed(err error) bool {
	// Winsock reports different errno values than the portable POSIX constants.
	return errors.Is(err, syscall.WSAECONNRESET) || errors.Is(err, syscall.WSAECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE)
}
