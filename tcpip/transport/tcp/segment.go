package tcp

import (
	"log"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/stack"
	"sync/atomic"
)

// tcp 太复杂了 专门写一个协议解析器

// segment 表示一个 TCP 段。它保存有效负载和解析的 TCP 段信息，并且可以添加到侵入列表中
type segment struct {
	segmentEntry
	refCnt int32
	id     stack.TransportEndpointID
	route  stack.Route
	data   buffer.VectorisedView
	// views is used as buffer for data when its length is large
	// enough to store a VectorisedView.
	views [8]buffer.View
	// TODO 需要添加
}

func newSegment(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) *segment {
	s := &segment{refCnt: 1, id: id, route: r.Clone()}
	s.data = vv.Clone(s.views[:])
	return s
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
	log.Println(header.TCP(s.data.First()))
	return false
}
