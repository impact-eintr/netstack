package ipv4

import (
	"encoding/binary"
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
)

/*
 ICMP 的全称是 Internet Control Message Protocol 。与 IP 协议一样同属 TCP/IP 模型中的网络层，并且 ICMP 数据包是包裹在 IP 数据包中的

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   不同的Type和Code有不同的内容            	 |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type echoRequest struct {
	r stack.Route
	v buffer.View
}

// handleControl处理ICMP数据包包含导致ICMP发送的原始数据包的标头的情况。
// 此信息用于确定必须通知哪个传输端点有关ICMP数据包。
func (e *endpoint) handleControl(typ stack.ControlType, extra uint32, vv buffer.VectorisedView) {
	h := header.IPv4(vv.First())

	// We don't use IsValid() here because ICMP only requires that the IP
	// header plus 8 bytes of the transport header be included. So it's
	// likely that it is truncated, which would cause IsValid to return
	// false.
	//
	// Drop packet if it doesn't have the basic IPv4 header or if the
	// original source address doesn't match the endpoint's address.
	if len(h) < header.IPv4MinimumSize || h.SourceAddress() != e.id.LocalAddress {
		return
	}

	hlen := int(h.HeaderLength())
	if vv.Size() < hlen || h.FragmentOffset() != 0 {
		// We won't be able to handle this if it doesn't contain the
		// full IPv4 header, or if it's a fragment not at offset 0
		// (because it won't have the transport header).
		return
	}

	// Skip the ip header, then deliver control message.
	vv.TrimFront(hlen)
	p := h.TransportProtocol()
	e.dispatcher.DeliverTransportControlPacket(e.id.LocalAddress, h.DestinationAddress(), ProtocolNumber, p, typ, extra, vv)
}

// 处理ICMP报文
func (e *endpoint) handleICMP(r *stack.Route, vv buffer.VectorisedView) {
	v := vv.First()
	if len(v) < header.ICMPv4MinimumSize {
		return
	}
	h := header.ICMPv4(v)

	// 更具icmp的类型来进行相应的处理
	switch h.Type() {
	case header.ICMPv4Echo: // icmp echo请求
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		log.Printf("ICMP echo")
		vv.TrimFront(header.ICMPv4MinimumSize) // 去掉头部
		req := echoRequest{r: r.Clone(), v: vv.ToView()}
		select {
		case e.echoRequests <- req: // 发送给echoReplier处理 在那里会重新组一个头部
		default:
			req.r.Release()
		}

	case header.ICMPv4EchoReply: // icmp echo响应
		if len(v) < header.ICMPv4EchoMinimumSize {
			return
		}
		e.dispatcher.DeliverTransportPacket(r, header.ICMPv4ProtocolNumber, vv)

	case header.ICMPv4DstUnreachable: // 目标不可达
		if len(v) < header.ICMPv4DstUnreachableMinimumSize {
			return
		}
		vv.TrimFront(header.ICMPv4DstUnreachableMinimumSize)
		switch h.Code() {
		case header.ICMPv4PortUnreachable: // 端口不可达
			e.handleControl(stack.ControlPortUnreachable, 0, vv)

		case header.ICMPv4FragmentationNeeded: // 需要进行分片但设置不分片标志
			mtu := uint32(binary.BigEndian.Uint16(v[header.ICMPv4DstUnreachableMinimumSize-2:]))
			e.handleControl(stack.ControlPacketTooBig, calculateMTU(mtu), vv)
		}
	}
}

// 处理icmp echo请求的goroutine
func (e *endpoint) echoReplier() {
	for req := range e.echoRequests {
		sendPing4(&req.r, 0, req.v)
		req.r.Release()
	}
}

// 根据icmp echo请求，封装icmp echo响应报文，并传给ip层处理
func sendPing4(r *stack.Route, code byte, data buffer.View) *tcpip.Error {
	hdr := buffer.NewPrependable(header.ICMPv4EchoMinimumSize + int(r.MaxHeaderLength()))

	icmpv4 := header.ICMPv4(hdr.Prepend(header.ICMPv4EchoMinimumSize))
	icmpv4.SetType(header.ICMPv4EchoReply)
	icmpv4.SetCode(code)
	copy(icmpv4[header.ICMPv4MinimumSize:], data)
	data = data[header.ICMPv4EchoMinimumSize-header.ICMPv4MinimumSize:]
	icmpv4.SetChecksum(^header.Checksum(icmpv4, header.Checksum(data, 0)))

	log.Printf("ICMP 回应报文组完 再次包装到IP报文")
	// 传给ip层处理
	return r.WritePacket(hdr, data.ToVectorisedView(), header.ICMPv4ProtocolNumber, r.DefaultTTL())
}
