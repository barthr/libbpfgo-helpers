package bpfutil

import (
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
)

var (
	// currently we have these as "global" variables since they are used throughout the program
	DnsProbeModule *bpf.Module
	DnsTcModule    *bpf.Module
)

func LoadModuleFromFile(path string) (*bpf.Module, error) {
	var err error
	module, err := bpf.NewModuleFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	err = module.BPFLoadObject()
	if err != nil {
		return nil, fmt.Errorf("failed loading bpf module on path %s: %w", path, err)
	}
	return module, nil
}

func LoadDnsProbeModule(path string) error {
	var err error
	DnsProbeModule, err = LoadModuleFromFile(path)
	return err
}

func LoadDnsTcModule(path string) error {
	var err error
	DnsTcModule, err = LoadModuleFromFile(path)
	return err
}
