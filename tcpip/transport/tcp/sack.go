package tcp

import (
	"netstack/tcpip/header"
	"netstack/tcpip/seqnum"
)

const (
	// MaxSACKBlocks 是接收端存储的最大SACK数
	MaxSACKBlocks = 6
)

// UpdateSACKBlocks 更新SACK块列表以包含 segStart-segEnd 指定的段，只有没有被消费掉的seg才会被用来更新sack。
// 如果该段恰好是无序传递，那么sack.blocks中的第一个块总是包括由 segStart-segEnd 标识的段。
func UpdateSACKBlocks(sack *SACKInfo, segStart seqnum.Value, segEnd seqnum.Value, rcvNxt seqnum.Value) {
	newSB := header.SACKBlock{Start: segStart, End: segEnd}
	if sack.NumBlocks == 0 {
		sack.Blocks[0] = newSB
		sack.NumBlocks = 1
		return
	}
	var n = 0
	for i := 0; i < sack.NumBlocks; i++ {
		start, end := sack.Blocks[i].Start, sack.Blocks[i].End
		if end.LessThanEq(start) || start.LessThanEq(rcvNxt) {
			// Discard any invalid blocks where end is before start
			// and discard any sack blocks that are before rcvNxt as
			// those have already been acked.
			continue
		}
		if newSB.Start.LessThanEq(end) && start.LessThanEq(newSB.End) {
			// Merge this SACK block into newSB and discard this SACK
			// block.
			if start.LessThan(newSB.Start) {
				newSB.Start = start
			}
			if newSB.End.LessThan(end) {
				newSB.End = end
			}
		} else {
			// Save this block.
			sack.Blocks[n] = sack.Blocks[i]
			n++
		}
	}
	if rcvNxt.LessThan(newSB.Start) {
		// If this was an out of order segment then make sure that the
		// first SACK block is the one that includes the segment.
		//
		// See the first bullet point in
		// https://tools.ietf.org/html/rfc2018#section-4
		if n == MaxSACKBlocks {
			// If the number of SACK blocks is equal to
			// MaxSACKBlocks then discard the last SACK block.
			n--
		}
		for i := n - 1; i >= 0; i-- {
			sack.Blocks[i+1] = sack.Blocks[i]
		}
		sack.Blocks[0] = newSB
		n++
	}
	sack.NumBlocks = n
}

// TrimSACKBlockList 通过删除/修改 start为 < rcvNext 的任何块来更新sack块列表
func TrimSACKBlockList(sack *SACKInfo, rcvNxt seqnum.Value) {
	n := 0
	for i := 0; i < sack.NumBlocks; i++ { // 遍历
		if sack.Blocks[i].End.LessThanEq(rcvNxt) {
			continue
		}
		if sack.Blocks[i].Start.LessThan(rcvNxt) {
			sack.Blocks[i].Start = rcvNxt
		}
		sack.Blocks[n] = sack.Blocks[i]
		n++
	}
	sack.NumBlocks = n
}
