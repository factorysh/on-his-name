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
	log    *log.Logger
}

func New(l *log.Logger) *Output {
	return &Output{
		output: make(chan []byte),
		log:    l,
	}
}

func (o *Output) GetOutputChannel() chan []byte {
	return o.output
}

func (o *Output) RunOutputLoop() {
	dt := &dnstap.Dnstap{}
	for frame := range o.output {
		if err := proto.Unmarshal(frame, dt); err != nil {
			o.log.Print(err)
			break
		}
		fmt.Println("Type", dt.Type)
		spew.Dump(dt)
	}
}

func (o *Output) Close() {

}
