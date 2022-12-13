package tcp

import (
	"netstack/sleep"
	"time"
)

type timerState int

const (
	timerStateDisabled timerState = iota
	timerStateEnabled
	timerStateOrphaned
)

// 定时器的实现
type timer struct {
	state timerState

	// target is the expiration time of the current timer. It is only
	// meaningful in the enabled state.
	target time.Time

	// runtimeTarget is the expiration time of the runtime timer. It is
	// meaningful in the enabled and orphaned states.
	runtimeTarget time.Time

	// timer is the runtime timer used to wait on.
	timer *time.Timer
}

// init initializes the timer. Once it expires, it the given waker will be
// asserted.
func (t *timer) init(w *sleep.Waker) {
	t.state = timerStateDisabled

	// Initialize a runtime timer that will assert the waker, then
	// immediately stop it.
	t.timer = time.AfterFunc(time.Hour, func() {
		w.Assert()
	})
	t.timer.Stop()
}

// cleanup frees all resources associated with the timer.
func (t *timer) cleanup() {
	t.timer.Stop()
}

// 检查是否过期
func (t *timer) checkExpiration() bool {
	if t.state == timerStateOrphaned {
		t.state = timerStateDisabled
		return false
	}

	now := time.Now()
	if now.Before(t.target) {
		t.runtimeTarget = t.target
		t.timer.Reset(t.target.Sub(now)) // ??这一步是为了什么
		return false
	}

	t.state = timerStateDisabled
	return true
}

// 关闭计时器 设置其状态为一个孤儿
func (t *timer) disable() {
	if t.state != timerStateDisabled {
		t.state = timerStateOrphaned
	}
}

// 开启计时器
func (t *timer) enable(d time.Duration) {
	t.target = time.Now().Add(d)

	// Check if we need to set the runtime timer.
	if t.state == timerStateDisabled || t.target.Before(t.runtimeTarget) {
		t.runtimeTarget = t.target
		t.timer.Reset(d)
	}

	t.state = timerStateEnabled
}

// 检验计时器是否已经启动
func (t *timer) enabled() bool {
	return t.state == timerStateEnabled
}
