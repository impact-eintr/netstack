package logger

import (
	"log"
	"sync"
)

/*
logger.GetInstance(IP|TCP)

logger.GetInstance().Info(logger.IP, msg) // 会输出

logger.GetInstance().Info(logger.UDP, msg) // 不会输出
*/

const (
	// ETH 以太网
	ETH = 1 << iota
	IP
	ARP
	UDP
	TCP
	// HANDSHAKE 三次握手 四次挥手
	HANDSHAKE
)

type logger struct {
	flags uint8
}

var instance *logger
var once sync.Once

// GetInstance 获取日志实例
func GetInstance() *logger {
	once.Do(func() {
		instance = &logger{
			//flags: 255,
		}
	})
	return instance
}

// SetFlags 设置输出类型
func SetFlags(flags uint8) {
	GetInstance().flags = flags
}

func (l *logger) Info(mask uint8, f func()) {
	if mask&l.flags != 0 {
		f()
	}
}

func (l *logger) info(f func()) {
	f()
}

func TODO(msg string) {
	GetInstance().info(func() {
		log.Println("TODO: " + msg)
	})
}

func FIXME(msg string) {
	GetInstance().info(func() {
		log.Fatal("FIXME: " + msg)
	})
}
