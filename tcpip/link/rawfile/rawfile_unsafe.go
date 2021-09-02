package rawfile

import (
	"syscall"
	"unsafe"

	"github.com/impact-eintr/netstack/tcpip"
)

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
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), syscall.SIOCGIFMTU, uintptr(&ifreq))
	if errno != 0 {
		return 0, errno
	}
	return uint32(ifreq.mtu), nil

}

func NonbolockingWrite(fd int, buf []byte) *tcpip.Error {
	var ptr unsafe.Pointer
	if len(buf) > 0 {
		ptr = unsafe.Pointer(&buf[0])
	}

	_, _, e := syscall.RawSyscall(syscall.SYS_WRITE,
		uintptr(fd), uintptr(ptr), uintptr(len(buf)))
	if e != 0 {
		return TranslationErrno(e)
	}
	return nil
}

func NonBolckingWrite2(fd int, b1, b2 []byte) *tcpip.Error {
	if len(b2) == 0 {
		return NonbolockingWrite(fd, b1)
	}

	iovec := [...]syscall.Iovec{
		{
			Base: &b1[0],
			Len:  uint64(len(b1)),
		},
		{
			Base: &b2[0],
			Len:  uint64(len(b2)),
		},
	}

	_, _, e := syscall.RawSyscall(syscall.SYS_WRITEV,
		uintptr(fd), uintptr(unsafe.Pointer(&iovec[0])), uintptr(len(iovec)))
	if e != 0 {
		return TranslationErrno(e)
	}
	return nil
}

type pollEvent struct {
	fd      int32
	events  int16
	revents int16
}
