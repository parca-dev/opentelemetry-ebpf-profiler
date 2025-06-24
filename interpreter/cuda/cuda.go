package cuda

// #include <stdlib.h>
// #include "../../support/ebpf/types.h"
import "C"

import (
	// "fmt"
	// "os"

	// "fmt"
	// "io"
	"errors"
	"fmt"
	"regexp"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	// "go.opentelemetry.io/ebpf-profiler/interpreter"
	// "go.opentelemetry.io/ebpf-profiler/libpf"
	// "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	// xh "go.opentelemetry.io/ebpf-profiler/x86helpers"
	// "golang.org/x/arch/x86/x86asm"
)

type data struct {
	launchSym libpf.Symbol
	// interpreter.InstanceStubs
}

var dsoRegex = regexp.MustCompile(`.*/libcudart\..*so`)

func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	if !dsoRegex.MatchString(info.FileName()) {
		log.Debugf("file %s is not libcudart", info.FileName())
		return nil, nil
	}

	file, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	launchSym, err := file.LookupSymbol("cudaLaunchKernel")
	if err != nil {
		return nil, err
	}
	if launchSym == nil {
		return nil, errors.New("symbol `cudaLaunchKernel` not found")
	}

	return &data{launchSym: *launchSym}, nil
}

type instance struct {
	interpreter.InstanceStubs
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {

	addr := uint64(d.launchSym.Address) + uint64(bias)

	procInfo := C.CudaProcInfo{
		launch_sym_addr: C.u64(addr),
		launch_sym_size: C.u64(d.launchSym.Size),
	}

	if err := ebpf.UpdateProcData(libpf.Cuda, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	fmt.Println("btv: successfully attached cuda")

	return &instance{}, nil

}

func (d data) Unload(_ interpreter.EbpfHandler) {}

func (i *instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.Cuda, pid)
}
