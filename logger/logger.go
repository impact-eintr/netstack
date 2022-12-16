package logger

import (
	"fmt"
	"log"
	"strings"
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

func TODO(msg string, v ...string) {
	GetInstance().info(func() {
		log.Printf("\033[1;37;41mTODO: %s\033[0m\n", msg+" "+strings.Join(v, " "))
	})
}

func FIXME(msg string, v ...string) {
	GetInstance().info(func() {
		log.Fatalf("\033[1;37;41mFIXME: %s\033[0m\n", msg+" "+strings.Join(v, " "))
	})
}

func NOTICE(msg string, v ...string) {
	GetInstance().info(func() {
		log.Printf("\033[1;37;41mNOTICE: %s\033[0m\n", msg+" "+strings.Join(v, " "))
	})
}

func COLORS() {
	for b := 40; b <= 47; b++ { // 背景色彩 = 40-47
		for f := 30; f <= 37; f++ { // 前景色彩 = 30-37
			for d := range []int{0, 1, 4, 5, 7, 8} { // 显示方式 = 0,1,4,5,7,8
				fmt.Printf(" %c[%d;%d;%dm%s(f=%d,b=%d,d=%d)%c[0m ", 0x1B, d, b, f, "", f, b, d, 0x1B)
			}
			fmt.Println("")
		}
		fmt.Println("")
	}
}
