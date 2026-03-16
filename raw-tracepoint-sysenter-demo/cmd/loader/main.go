package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	var objPath string
	flag.StringVar(&objPath, "obj", ".snx/build/raw_sysenter.o", "path to compiled eBPF object")
	flag.Parse()

	absObjPath, err := filepath.Abs(objPath)
	if err != nil {
		log.Fatalf("abs path for -obj: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock rlimit: %v", err)
	}

	spec, err := ebpf.LoadCollectionSpec(absObjPath)
	if err != nil {
		log.Fatalf("load collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("load collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["trace_raw_sys_enter"]
	if prog == nil {
		log.Fatalf("program %q not found in object", "trace_raw_sys_enter")
	}

	lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: prog,
	})
	if err != nil {
		log.Fatalf("attach raw tracepoint: %v", err)
	}
	defer lnk.Close()

	log.Printf("raw_tracepoint/sys_enter attached (stub program). Ctrl+C to detach.")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

