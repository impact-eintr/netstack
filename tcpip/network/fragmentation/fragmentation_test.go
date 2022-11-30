package fragmentation_test

import (
	"log"
	"math"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/link/channel"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/stack"
	"testing"
	"time"
)

const (
	stackLinkAddr = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c") // 0a:0a:0b:0b:0c:0c
	stackAddr1    = tcpip.Address("\x0a\x00\x00\x01")             // 10.0.0.1
	stackAddr2    = tcpip.Address("\x0a\x00\x00\x02")             // 10.0.0.2
	stackAddrBad  = tcpip.Address("\x0a\x00\x00\x03")             // 10.0.0.3
)

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack
	id     uint16
}

func newTestContext(t *testing.T) *testContext {
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName}, nil, stack.Options{})

	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, stackLinkAddr)
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr1); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr2); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		t.Fatalf("AddAddress for arp failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: "\x00\x00\x00\x00",
		Mask:        "\x00\x00\x00\x00",
		Gateway:     "",
		NIC:         1,
	}})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
		id:     uint16(time.Now().Unix() % math.MaxUint16),
	}
}

func (c *testContext) cleanup() {
	close(c.linkEP.C)
}

func TestFragmentationBase(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make(buffer.View, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)                  // 一个ARP请求
	copy(h.HardwareAddressSender(), senderMAC)  // Local MAC
	copy(h.ProtocolAddressSender(), senderIPv4) // Local IP

	inject := func(addr tcpip.Address) {
		copy(h.ProtocolAddressTarget(), addr)
		c.linkEP.Inject(arp.ProtocolNumber, v.ToVectorisedView()) // 往链路层注入一个arp报文 链路层将会自动分发它
	}

	inject(stackAddr1) // target IP  10.0.0.1
	select {
	case pkt := <-c.linkEP.C:
		if pkt.Proto != arp.ProtocolNumber {
			t.Fatalf("stackAddr1: expected ARP response, got network protocol number %v", pkt.Proto)
		}
		rep := header.ARP(pkt.Header)
		if !rep.IsValid() {
			t.Fatalf("stackAddr1: invalid ARP response len(pkt.Header)=%d", len(pkt.Header))
		}
		if tcpip.Address(rep.ProtocolAddressSender()) != stackAddr1 {
			t.Errorf("stackAddr1: expected sender to be set")
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
			t.Errorf("stackAddr1: expected sender to be stackLinkAddr, got %q", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Case #1 Time Out\n")
	}

	// 一个纯粹的IP报文 Part1
	pLen := ((1500 - header.EthernetMinimumSize - header.IPv4MinimumSize) >> 3) << 3
	v = make(buffer.View, header.IPv4MinimumSize+pLen)
	hdr := buffer.NewPrependable(header.IPv4MinimumSize)
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	buf := make(buffer.View, pLen)
	for i := range buf {
		buf[i] = 1
	}
	payload := buffer.NewVectorisedView(pLen, buf.ToVectorisedView().Views())
	length := uint16(hdr.UsedLength() + payload.Size())
	// ip首部编码
	ip.Encode(&header.IPv4Fields{
		IHL:            header.IPv4MinimumSize,
		TotalLength:    length,
		ID:             c.id,
		Flags:          0x1,
		FragmentOffset: 0,
		TTL:            255,
		Protocol:       uint8(0x6), // tcp 伪装报文
		SrcAddr:        senderIPv4,
		DstAddr:        stackAddr1,
	})
	//ip.SetFlagsFragmentOffset()
	// 计算校验和和设置校验和
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(v, ip)
	copy(v[header.IPv4MinimumSize:], payload.First())

	inject = func(addr tcpip.Address) {
		copy(h.ProtocolAddressTarget(), addr)
		c.linkEP.Inject(ipv4.ProtocolNumber, v.ToVectorisedView()) // 往链路层注入一个arp报文 链路层将会自动分发它
	}

	inject(stackAddr1)

	// 一个纯粹的IP报文 Part2
	pLen = 256
	v = make(buffer.View, header.IPv4MinimumSize+pLen)
	payload = buffer.NewVectorisedView(pLen, buf.ToVectorisedView().Views())
	length = uint16(hdr.UsedLength() + payload.Size())
	// ip首部编码
	ip.Encode(&header.IPv4Fields{
		IHL:            header.IPv4MinimumSize,
		TotalLength:    length,
		ID:             c.id,
		FragmentOffset: 1464,
		TTL:            255,
		Protocol:       uint8(0x6), // tcp 伪装报文
		SrcAddr:        senderIPv4,
		DstAddr:        stackAddr1,
	})
	//ip.SetFlagsFragmentOffset()
	// 计算校验和和设置校验和
	ip.SetChecksum(^ip.CalculateChecksum())
	copy(v, ip)
	copy(v[header.IPv4MinimumSize:], payload.First())

	inject(stackAddr1)

	msg := <-c.linkEP.C
	log.Println(msg.Header)

}
