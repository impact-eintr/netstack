package logger

import (
	"sync"
)

const (
	IP = 1 << iota
	UDP
	TCP
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

/*
logger.GetInstance(IP|TCP)

logger.GetInstance().Info(logger.IP, msg) // 会输出

logger.GetInstance().Info(logger.UDP, msg) // 不会输出


*/

func (l *logger) Info(mask uint8, f func()) {
	if mask&l.flags != 0 {
		f()
	}
}
