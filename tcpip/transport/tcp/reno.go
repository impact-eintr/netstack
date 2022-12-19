package tcp

import "log"

type renoState struct {
	s *sender
}

// 新建reno算法对象
func newRenoCC(s *sender) *renoState {
	return &renoState{s: s}
}

// HandleNDupAcks implements congestionControl.HandleNDupAcks.
// 当收到三个重复ack时，调用 HandleNDupAcks 来处理。
func (r *renoState) HandleNDupAcks() {
	// A retransmit was triggered due to nDupAckThreshold
	// being hit. Reduce our slow start threshold.
	// 减小慢启动阀值
	log.Fatal("快速重传开始")
	r.reduceSlowStartThreshold()
}

func (r *renoState) HandleRTOExpired() {

}

func (r *renoState) Update(packetsAcked int) {

}

func (r *renoState) PostRecovery() {

}
