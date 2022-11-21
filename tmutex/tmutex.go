package tmutex

import (
	"sync/atomic"
)

type Mutex struct {
	v int32
	ch chan struct{}
}

func (m *Mutex) Init() {
	m.v = 1
	m.ch = make(chan struct{}, 1)
}

func (m *Mutex) Lock() {
	// ==0时 只有一个锁持有者
	if atomic.AddInt32(&m.v, -1) == 0 {
		return
	}
	// !=0时 有多个想持有锁者
	for {
		if v := atomic.LoadInt32(&m.v);v >= 0 && atomic.SwapInt32(&m.v, -1) == 1 {
			return
		}
		<-m.ch // 排队阻塞 等待锁释放
	}
}

func (m *Mutex) TryLock() bool {
	v := atomic.LoadInt32(&m.v)
	if v <= 0 {
		return false
	}
	// CAS操作需要输入两个数值，一个旧值（期望操作前的值）和一个新值，
	// 在操作期间先比较下旧值有没有发生变化，
	// 如果没有发生变化，才交换成新值，发生了变化则不交换。
	return atomic.CompareAndSwapInt32(&m.v, 1, 0)
}

func (m *Mutex) Unlock() {
	if atomic.SwapInt32(&m.v, 1) == 0 { // 没有任何持有者
		return
	}

	select {
	case m.ch <- struct{}{}:
	default:
	}
}
