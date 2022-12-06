package tcp

import (
	"fmt"
	"log"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
	"netstack/tcpip/stack"
	"strings"
	"sync/atomic"
)

// tcp 太复杂了 专门写一个协议解析器 segment 是有种类之分的

// Flags that may be set in a TCP segment.
const (
	flagFin = 1 << iota
	flagSyn
	flagRst
	flagPsh
	flagAck
	flagUrg
)

func flagString(flags uint8) string {
	var s []string
	if (flags & flagAck) != 0 {
		s = append(s, "ack")
	}
	if (flags & flagFin) != 0 {
		s = append(s, "fin")
	}
	if (flags & flagPsh) != 0 {
		s = append(s, "psh")
	}
	if (flags & flagRst) != 0 {
		s = append(s, "rst")
	}
	if (flags & flagSyn) != 0 {
		s = append(s, "syn")
	}
	if (flags & flagUrg) != 0 {
		s = append(s, "urg")
	}
	return strings.Join(s, "|")
}

// segment 表示一个 TCP 段。它保存有效负载和解析的 TCP 段信息，并且可以添加到侵入列表中
type segment struct {
	segmentEntry
	refCnt int32 // 引用计数
	id     stack.TransportEndpointID
	route  stack.Route
	data   buffer.VectorisedView
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View
	// TODO 需要解析
	viewToDeliver  int
	sequenceNumber seqnum.Value // tcp序号 第一个字节在整个报文的位置
	ackNumber      seqnum.Value // 确认号 希望继续获取的下一个字节序号
	flags          uint8
	window         seqnum.Size
	// parsedOptions stores the parsed values from the options in the segment.
	parsedOptions header.TCPOptions
	options       []byte
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) *segment {
	s := &segment{refCnt: 1, id: id, route: r.Clone()}
	s.data = vv.Clone(s.views[:])
	return s
}

func newSegmentFromView(r *stack.Route, id stack.TransportEndpointID, v buffer.View) *segment {
	s := &segment{
		refCnt: 1,
		id:     id,
		route:  r.Clone(),
	}
	s.views[0] = v
	s.data = buffer.NewVectorisedView(len(v), s.views[:1]) // TODO 为什么只复制1?
	return s
}

func (s *segment) clone() *segment {
	t := &segment{
		refCnt:         1,
		id:             s.id,
		sequenceNumber: s.sequenceNumber,
		ackNumber:      s.ackNumber,
		flags:          s.flags,
		window:         s.window,
		route:          s.route.Clone(),
		viewToDeliver:  s.viewToDeliver,
	}
	t.data = s.data.Clone(t.views[:])
	return t
}

func (s *segment) flagIsSet(flag uint8) bool {
	return (s.flags & flag) != 0
}

func (s *segment) decRef() {
	if atomic.AddInt32(&s.refCnt, -1) == 0 {
		s.route.Release()
	}
}

func (s *segment) incRef() {
	atomic.AddInt32(&s.refCnt, 1)
}

func (s *segment) parse() bool {
	h := header.TCP(s.data.First())
	offset := int(h.DataOffset())
	if offset < header.TCPMinimumSize || offset > len(h) {
		return false
	}
	s.options = h.Options()
	s.parsedOptions = header.ParseTCPOptions(s.options)

	log.Println(h)
	fmt.Println(s.parsedOptions)

	s.data.TrimFront(offset)

	s.sequenceNumber = seqnum.Value(h.SequenceNumber())
	s.ackNumber = seqnum.Value(h.AckNumber())
	s.flags = h.Flags() // U|A|P|R|S|F
	s.window = seqnum.Size(h.WindowSize())
	return true
}
