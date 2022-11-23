package fdbased

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/stack"
	"syscall"
	"testing"
)

const (
	mtu = 1500
	laddr = tcpip.LinkAddress("\x11\x22\x33\x44\x55\x66")
	raddr = tcpip.LinkAddress("\x77\x88\x99\xaa\xbb\xcc")
	proto = 10
)

type packetInfo struct {
	raddr tcpip.LinkAddress
	proto tcpip.NetworkProtocolNumber
	contents buffer.View
}

type context struct {
	t *testing.T
	fds [2]int
	ep stack.LinkEndpoint
	ch chan packetInfo
	done chan struct{}
}

func NewContext(t *testing.T, opt *Options) *context {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}

	done := make(chan struct{}, 1)
	opt.ClosedFunc = func(*tcpip.Error) {
		done <- struct{}{}
	}

	opt.FD = fds[1]
	ep := stack.FindLinkEndpoint(New(opt)).(*endpoint)

	c := &context{
		t: t,
		fds: fds,
		ep:ep,
		ch: make(chan packetInfo, 100),
		done: done,
	}

	ep.Attach(c)

	return c
}


func (c *context) DeliverNetworkPacket(linkEP stack.LinkEndpoint,
	dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	c.ch <- packetInfo{dstLinkAddr, protocol, vv.ToView()}
}

func TestFdbased(t *testing.T) {
}
