package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type ForkEvent struct {
	ParentPid  uint32
	ChildPid   uint32
	ParentComm [16]byte
	ChildComm  [16]byte
}

func main() {

	spec, err := ebpf.LoadCollectionSpec(".snx/build/sched_process_fork_monitor.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}

	objs := struct {
		ForkTrace *ebpf.Program `ebpf:"fork_trace"`
		Events    *ebpf.Map     `ebpf:"events"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	tp, err := link.Tracepoint(
		"sched",
		"sched_process_fork",
		objs.ForkTrace,
		nil,
	)
	if err != nil {
		log.Fatalf("attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf reader: %v", err)
	}
	defer rd.Close()

	fmt.Println("Fork monitor running...")

	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatalf("read ringbuf: %v", err)
		}

		var event ForkEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		fmt.Printf(
			"Fork: parent=%d (%s) → child=%d (%s)\n",
			event.ParentPid,
			event.ParentComm,
			event.ChildPid,
			event.ChildComm,
		)
	}
}