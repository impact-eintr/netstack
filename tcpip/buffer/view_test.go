package buffer

import (
	"fmt"
	"testing"
)

func TestBaseView(t *testing.T) {
	buffer1 := []byte("hello world")
	buffer2 := []byte("test test test")
	bv1 := NewViewFromBytes(buffer1)
	bv2 := NewViewFromBytes(buffer2)
	views := NewVectorisedView(2, []View{bv1, bv2})
	fmt.Println(string(views.ToView()))
}
