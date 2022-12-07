package tcp

import (
	"netstack/tcpip/header"
	"sync"
)

type segmentQueue struct {
	mu    sync.Mutex
	list  segmentList // 队列实现
	limit int         // 队列容量
	used  int         // 队列长度
}

func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	r := q.used == 0
	q.mu.Unlock()
	return r
}

func (q *segmentQueue) enqueue(s *segment) bool {
	q.mu.Lock()
	r := q.used < q.limit
	if r {
		q.list.PushBack(s)
		q.used += s.data.Size() + header.TCPMinimumSize
	}
	q.mu.Unlock()

	return r
}

func (q *segmentQueue) dequeue() *segment {
	q.mu.Lock()
	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
		q.used -= s.data.Size() + header.TCPMinimumSize
	}
	q.mu.Unlock()

	return s
}

func (q *segmentQueue) setLimit(limit int) {
	q.mu.Lock()
	q.limit = limit
	q.mu.Unlock()
}
