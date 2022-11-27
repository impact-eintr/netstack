package header_test

import (
	"log"
	"math/rand"
	"netstack/tcpip/header"
	"testing"
	"time"
)

func TestChecksum(t *testing.T) {
	buf := make([]byte, 1024)
	rand.Seed(time.Now().Unix())
	for i := range buf {
		buf[i] = uint8(rand.Intn(255))
	}
	sum := header.Checksum(buf, 0)
	log.Println(sum)
}
