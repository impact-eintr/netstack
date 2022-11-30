package tmutex

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestBasicLock(t *testing.T) {
	var race = 0
	var m Mutex
	m.Init()

	m.Lock()

	go func(){
		m.Lock()
		race++
		m.Unlock()
	}()

	go func(){
		m.Lock()
		race++
		m.Unlock()
	}()

	runtime.Gosched() // 让渡cpu
	race++

	m.Unlock()

	time.Sleep(time.Second)
}

func TestShutOut(t *testing.T) {

	a := 1
	if a < 3 || func() bool {
		fmt.Println("ShutOut")
		return false
	}() {
		t.Logf("Ok\n")
	}

}
