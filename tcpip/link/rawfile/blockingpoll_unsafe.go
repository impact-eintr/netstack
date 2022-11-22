package rawfile

import (
	"syscall"
	"netstack/tcpip"
	"unsafe"
)

// GetMTU 确定网络接口设备的 MTU
func GetMTU(name string) (uint32, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}

	defer syscall.Close(fd)

	var ifreq struct {
		name [16]byte
		mtu  int32
		_    [20]byte
	}

	copy(ifreq.name[:], name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFMTU,              uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		return 0, errno
	}

	return uint32(ifreq.mtu), nil
}

type pollEvent struct {
	fd int32
	events int16
	revents int16
}

func BlockingRead(fd int, b []byte) (int, *tcpip.Error) {
	for {
		n, _, e := syscall.RawSyscall(syscall.SYS_READ, uintptr(fd),
			uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))) // <unistd.h> read(fd,buf,len)
		if e == 0 {
			return int(n), nil
		}

		event := pollEvent{
			fd: int32(fd),
			events: 1, // POLLIN
		}

		_, e = blockingPoll(&event, 1, -1)
		if e != 0 && e != syscall.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

func BlockingReadv(fd int, iovecs []syscall.Iovec) (int, *tcpip.Error) {
	for {
		n, _, e := syscall.RawSyscall(syscall.SYS_READV, uintptr(fd), uintptr(unsafe.                 Pointer(&iovecs[0])), uintptr(len(iovecs)))
		if e == 0 {
			return int(n), nil
		}

		event := pollEvent{
			fd:     int32(fd),
			events: 1, // POLLIN
		}

		_, e = blockingPoll(&event, 1, -1)
		if e != 0 && e != syscall.EINTR {
			return 0, TranslateErrno(e)
		}
	}
}

func blockingPoll(fds *pollEvent, nfds int, timeout int64) (int, syscall.Errno) {
	n, _, e := syscall.Syscall(syscall.SYS_POLL, uintptr(unsafe.Pointer(fds)),
		uintptr(nfds), uintptr(timeout))
	return int(n), e
}
