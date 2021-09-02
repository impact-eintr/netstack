package rawfile

import (
	"syscall"
	"unsafe"
)

func blockingPoll(fds *pollEvent, nfds int, timeout int64) (int, syscall.Errno) {
	n, _, e := syscall.Syscall(syscall.SYS_POLL,
		uintptr(unsafe.Pointer(fds)), uintptr(nfds), uintptr(timeout))
	return int(n), e
}
