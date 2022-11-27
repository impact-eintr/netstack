package hash

import (
	"crypto/rand"
	"encoding/binary"
	"netstack/tcpip/header"
)

var hashIV = RandN32(1)[0]

// RandN32 生成 n 个加密随机 32 位数字的切片
func RandN32(n int) []uint32 {
	b := make([]byte, 4*n)
	if _, err := rand.Read(b); err != nil {
		panic("unable to get random numbers: " + err.Error())
	}
	r := make([]uint32, n)
	for i := range r {
		r[i] = binary.LittleEndian.Uint32(b[4*i : (4*i + 4)])
	}
	return r
}

func Hash3Words(a, b, c, initval uint32) uint32 {
	const iv = 0xdeadbeef + (3 << 2)
	initval += iv

	a += initval
	b += initval
	c += initval

	c ^= b
	c -= rol32(b, 14)
	a ^= c
	a -= rol32(c, 11)
	b ^= a
	b -= rol32(a, 25)
	c ^= b
	c -= rol32(b, 16)
	a ^= c
	a -= rol32(c, 4)
	b ^= a
	b -= rol32(a, 14)
	c ^= b
	c -= rol32(b, 24)

	return c
}

// 根据id，源ip，目的ip和协议类型得到hash值
func IPv4FragmentHash(h header.IPv4) uint32 {
	x := uint32(h.ID())<<16 | uint32(h.Protocol())
	t := h.SourceAddress()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(x, y, z, hashIV)
}

func IPv6FragmentHash(h header.IPv6, f header.IPv6Fragment) uint32 {
	t := h.SourceAddress()
	y := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	t = h.DestinationAddress()
	z := uint32(t[0]) | uint32(t[1])<<8 | uint32(t[2])<<16 | uint32(t[3])<<24
	return Hash3Words(f.ID(), y, z, hashIV)
}

func rol32(v, shift uint32) uint32 {
	return (v << shift) | (v >> ((-shift) & 31))
}
