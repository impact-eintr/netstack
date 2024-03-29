package fdbased

import (
	"fmt"
	"math/rand"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"reflect"
	"syscall"
	"testing"
	"time"
)

const (
	mtu   = 1500
	laddr = tcpip.LinkAddress("\x65\x66\x67\x68\x69\x70")
	raddr = tcpip.LinkAddress("\x71\x72\x73\x74\x75\x76")
	proto = 10
)

type packetInfo struct {
	raddr    tcpip.LinkAddress
	proto    tcpip.NetworkProtocolNumber
	contents buffer.View
}

type context struct {
	t    *testing.T
	fds  [2]int
	ep   stack.LinkEndpoint
	ch   chan packetInfo // 信道
	done chan struct{}   // 通知退出
}

func newContext(t *testing.T, opt *Options) *context {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}

	done := make(chan struct{}, 1)
	opt.ClosedFunc = func(*tcpip.Error) {
		done <- struct{}{}
	}

	opt.FD = fds[1]
	ep := stack.FindLinkEndpoint(New(opt)).(*endpoint) // 找到端口实现

	c := &context{
		t:    t,
		fds:  fds,
		ep:   ep,
		ch:   make(chan packetInfo, 100),
		done: done,
	}

	ep.Attach(c) // 启动端口 后台阻塞等待

	return c
}

func (c *context) cleanup() {
	syscall.Close(c.fds[0])
	<-c.done
	syscall.Close(c.fds[1])
}

func (c *context) DeliverNetworkPacket(linkEP stack.LinkEndpoint,
	dstLinkAddr, srcLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	c.ch <- packetInfo{dstLinkAddr, protocol, vv.ToView()}
}

func TestFdbased(t *testing.T) {
	c := newContext(t, &Options{MTU: mtu, Address: tcpip.LinkAddress(laddr)})
	defer c.cleanup()

	// Build header
	hdr := buffer.NewPrependable(int(c.ep.MaxHeaderLength()) + 100) // 114
	b := hdr.Prepend(100)                                           // payload
	for i := range b {
		b[i] = uint8(rand.Intn(256))
	}

	// Build payload and write
	payload := make(buffer.View, 1024) // payload len = 1024
	for i := range payload {
		payload[i] = uint8(rand.Intn(256))
	}

	if err := c.ep.WritePacket(&stack.Route{RemoteLinkAddress: raddr}, hdr,
		payload.ToVectorisedView(), proto); err != nil {
		panic(err)
	}

	b = make([]byte, mtu)
	n, err := syscall.Read(c.fds[0], b)
	if err != nil {
		panic(err)
	}
	b = b[:n]
	h := header.Ethernet(b)
	if h.DestinationAddress() != raddr || h.SourceAddress() != laddr {
		panic("diff Err")
	}
}

func TestPreserveSrcAddress(t *testing.T) {
	baddr := tcpip.LinkAddress("\xcc\xbb\xaa\x77\x88\x99")

	c := newContext(t, &Options{Address: laddr, MTU: mtu})
	defer c.cleanup()

	// Set LocalLinkAddress in route to the value of the bridged address.
	r := &stack.Route{
		RemoteLinkAddress: raddr,
		LocalLinkAddress:  baddr,
	}

	// WritePacket panics given a prependable with anything less than
	// the minimum size of the ethernet header.
	hdr := buffer.NewPrependable(header.EthernetMinimumSize)
	if err := c.ep.WritePacket(r, hdr, buffer.VectorisedView{}, proto); err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Read from the FD, then compare with what we wrote.
	b := make([]byte, mtu)
	n, err := syscall.Read(c.fds[0], b)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	b = b[:n]
	h := header.Ethernet(b)

	if a := h.SourceAddress(); a != baddr {
		t.Fatalf("SourceAddress() = %v, want %v", a, baddr)
	}
}

func TestDeliverPacket(t *testing.T) {
	lengths := []int{100, 1000}
	for _, plen := range lengths {
		t.Run(fmt.Sprintf("PayloadLen=%v", plen), func(t *testing.T) {
			c := newContext(t, &Options{Address: laddr, MTU: mtu})
			defer c.cleanup()

			// Build packet.
			b := make([]byte, plen)
			all := b
			for i := range b {
				b[i] = uint8(rand.Intn(256))
			}

			hdr := make(header.Ethernet, header.EthernetMinimumSize)
			hdr.Encode(&header.EthernetFields{
				SrcAddr: raddr,
				DstAddr: laddr,
				Type:    proto,
			})
			all = append(hdr, b...)

			// Write packet via the file descriptor.
			if _, err := syscall.Write(c.fds[0], all); err != nil {
				t.Fatalf("Write failed: %v", err)
			}

			// Receive packet through the endpoint.
			select {
			case pi := <-c.ch:
				want := packetInfo{
					raddr:    raddr,
					proto:    proto,
					contents: b,
				}

				if !reflect.DeepEqual(want, pi) {
					t.Fatalf("Unexpected received packet: %+v, want %+v", pi, want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("Timed out waiting for packet")
			}
		})
	}
}

//func TestBufConfigMaxLength(t *testing.T) {
//      got := 0
//      for _, i := range BufConfig {
//              got += i
//      }
//      want := header.MaxIPPacketSize // maximum TCP packet size
//      if got < want {
//              t.Errorf("total buffer size is invalid: got %d, want >= %d", got, want)
//      }
//}

func TestBufConfigFirst(t *testing.T) {
	// The stack assumes that the TCP/IP header is enterily contained in the first view.
	// Therefore, the first view needs to be large enough to contain the maximum TCP/IP
	// header, which is 120 bytes (60 bytes for IP + 60 bytes for TCP).
	want := 120
	got := BufConfig[0]
	if got < want {
		t.Errorf("first view has an invalid size: got %d, want >= %d", got, want)
	}
}

func build(bufConfig []int) *endpoint {
	e := &endpoint{
		views:  make([]buffer.View, len(bufConfig)),
		iovecs: make([]syscall.Iovec, len(bufConfig)),
	}
	e.allocateViews(bufConfig)
	return e
}

var capLengthTestCases = []struct {
	comment     string
	config      []int
	n           int
	wantUsed    int
	wantLengths []int
}{
	{
		comment:     "Single slice",
		config:      []int{2},
		n:           1,
		wantUsed:    1,
		wantLengths: []int{1},
	},
	{
		comment:     "Multiple slices",
		config:      []int{1, 2},
		n:           2,
		wantUsed:    2,
		wantLengths: []int{1, 1},
	},
	{
		comment:     "Entire buffer",
		config:      []int{1, 2},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2},
	},
	{
		comment:     "Entire buffer but not on the last slice",
		config:      []int{1, 2, 3},
		n:           3,
		wantUsed:    2,
		wantLengths: []int{1, 2, 3},
	},
}

func TestCapLength(t *testing.T) {
	for _, c := range capLengthTestCases {
		e := build(c.config)
		used := e.capViews(c.n, c.config)
		if used != c.wantUsed {
			t.Errorf("Test \"%s\" failed when calling capViews(%d, %v). Got %d. Want %d", c.comment, c.n, c.config, used, c.wantUsed)
		}
		lengths := make([]int, len(e.views))
		for i, v := range e.views {
			lengths[i] = len(v)
		}
		if !reflect.DeepEqual(lengths, c.wantLengths) {
			t.Errorf("Test \"%s\" failed when calling capViews(%d, %v). Got %v. Want %v", c.comment, c.n, c.config, lengths, c.wantLengths)
		}

	}
}
