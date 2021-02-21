package output

import (
	"fmt"
	"log"

	"github.com/davecgh/go-spew/spew"
	dnstap "github.com/dnstap/golang-dnstap"
	"google.golang.org/protobuf/proto"
)

type Output struct {
	output chan []byte
	log    log.Logger
}

func New() *Output {
	return &Output{
		output: make(chan []byte),
	}
}

func (o *Output) GetOutputChannel() chan []byte {
	return o.output
}
func (o *Output) RunOutputLoop() {
	dt := &dnstap.Dnstap{}
	fmt.Println("ma loop")
	for frame := range o.output {
		if err := proto.Unmarshal(frame, dt); err != nil {
			o.log.Print(err)
			break
		}
		spew.Dump(dt)
	}

}
func (o *Output) Close() {
	fmt.Println("bim, on coupe")

}
