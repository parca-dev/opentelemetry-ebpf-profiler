package parcagpu

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

type parcaGpuManager struct {
	readers map[libpf.PID]parcaGpuReader
}

type parcaGpuReader struct {
	timesAwaitingTraces map[uint32]float32
	tracesAwaitingTimes map[uint32]*host.Trace
	pid                 libpf.PID
	// traceOutChan <-chan IdAndTrace
	traceInChan chan<- *host.Trace
}

// not thread safe
func (p *parcaGpuReader) addTrace(trace *host.Trace) *host.Trace {
	id := trace.ParcaGPUTraceID
	millis, ok := p.timesAwaitingTraces[id]
	if ok {
		delete(p.timesAwaitingTraces, id)
		trace.OffTime = int64(millis * 1000000.0)
		return trace
	}
	p.tracesAwaitingTimes[id] = trace
	return nil
}

// not thread safe
func (p *parcaGpuReader) addTime(id uint32, millis float32) *host.Trace {
	trace, ok := p.tracesAwaitingTimes[id]
	if ok {
		delete(p.tracesAwaitingTimes, id)
		trace.OffTime = int64(millis * 1000000.0)
		return trace
	}
	p.timesAwaitingTraces[id] = millis
	return nil
}

type idAndTime struct {
	id     uint32
	millis float32
}

func watchSocket(pid libpf.PID, timeOutChan chan<- idAndTime, ctx context.Context) error {
	path := fmt.Sprintf("\x00parcagpu.%d", pid)
	addr := net.UnixAddr{Name: path, Net: "unix"}
	conn, err := net.DialUnix("unix", nil, &addr)
	defer conn.Close()
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.SetReadDeadline(time.Now())
	}()
	buf := make([]byte, 8)
	for {
		_, err := io.ReadFull(conn, buf)
		if err != nil {
			return err
		}
		id := binary.LittleEndian.Uint32(buf[0:4])
		millisBits := binary.LittleEndian.Uint32(buf[4:8])
		millis := math.Float32frombits(millisBits)
		timeOutChan <- idAndTime{id, millis}
	}
}

func startParcaGpuReader(pid libpf.PID, ctx context.Context, cancel context.CancelFunc, traceOutChan chan<- *host.Trace) *parcaGpuReader {
	timeChan := make(chan idAndTime)
	traceChan := make(chan *host.Trace)

	go func() {
		err := watchSocket(pid, timeChan, ctx)
		log.Infof("parcagpu socket for %d hung up: %v", pid, err)
		cancel()
	}()

	rdr := &parcaGpuReader{
		timesAwaitingTraces: map[uint32]float32{},
		tracesAwaitingTimes: map[uint32]*host.Trace{},
		traceInChan:         traceChan,
	}

	go func() {
		for {
			select {
			case time := <-timeChan:
				fmt.Printf("[btv] got time and id: %f, 0x%x\n", time.millis, time.id)
				if trace := rdr.addTime(time.id, time.millis); trace != nil {
					fmt.Printf("[btv] trace complete: %d\n", trace.ParcaGPUTraceID)
					traceOutChan <- trace
				}
			case trace := <-traceChan:
				fmt.Printf("[btv] got trace with id: 0x%x\n", trace.ParcaGPUTraceID)
				if trace := rdr.addTrace(trace); trace != nil {
					fmt.Printf("[btv] trace complete: 0x%x\n", trace.ParcaGPUTraceID)
					traceOutChan <- trace
				}
			}
		}
	}()

	return rdr
}

type deviceAndInode struct {
	device uint64
	inode  uint64
}

func handleParcaGpu(ctx context.Context, cancel context.CancelFunc, traceOutChan chan<- *host.Trace, attachedDsos map[deviceAndInode]link.Link, pid libpf.PID, prog *cebpf.Program) (*parcaGpuReader, error) {
	fmt.Printf("[btv] handling %d\n", pid)

	// Get the mappings of pid
	proc := process.New(pid)
	mappings, _, err := proc.GetMappings()
	if err != nil {
		return nil, err
	}

	// find the one with parcagpu in the name
	idx := slices.IndexFunc(mappings, func(m process.Mapping) bool {
		return strings.Contains(m.Path, "libparcagpu.so")
	})
	if idx == -1 {
		return nil, errors.New("mapping for libparcagpu.so not found")
	}

	// stat to find the dev/inode
	// if it has not been attached to already, attach to `shim_inner`.
	dai := deviceAndInode{
		device: mappings[idx].Device,
		inode:  mappings[idx].Inode,
	}
	if _, ok := attachedDsos[dai]; !ok {

		x, err := link.OpenExecutable(mappings[idx].Path)
		if err != nil {
			return nil, err
		}
		uprobe, err := x.Uprobe("shim_inner", prog, &link.UprobeOptions{})
		if err != nil {
			return nil, err
		}

		attachedDsos[dai] = uprobe
	}

	//
	// in either case, see if we already have a ParcaGpuReader for this
	// pid. If not, create one and store it in a map (pid |-> ParcaGpuReader). The ParcaGpuReader will
	// maintain a map (id |-> time) of "times awaiting traces"
	// and (id |-> trace) of "traces awaiting times".
	//
	// It will connect to /tmp/parcagpu.{pid}
	// and listen for id/time correlations; we'll also notify it of new traces that require times.
	//
	// When either matches, pass it on to the reporter.

	rdr := startParcaGpuReader(pid, ctx, cancel, traceOutChan)
	return rdr, nil
}

// GetParcaGPUPIDs parses /proc/net/unix and returns a slice of PIDs
// for sockets named @parcagpu.<pid> in the abstract namespace.
func getParcaGPUPIDs() ([]libpf.PID, error) {
	file, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/net/unix: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Skip the header line
	if !scanner.Scan() {
		return nil, fmt.Errorf("file is empty or unreadable")
	}

	var pids []libpf.PID

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// The path (socket name) is typically the last field, if present
		if len(fields) < 8 {
			continue
		}
		path := fields[len(fields)-1]

		// Match abstract namespace socket and check for @parcagpu.<pid>
		before, after, found := strings.Cut(path, ".")
		if found && before == "@parcagpu" {
			pid, err := strconv.Atoi(after)
			if err != nil {
				continue
			}
			pids = append(pids, libpf.PID(pid))
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning file: %w", err)
	}

	return pids, nil
}

func StartParcaGpuHandler(traceInChan <-chan *host.Trace, traceOutChan chan<- *host.Trace, prog *cebpf.Program) error {
	pidChan := make(chan libpf.PID)

	go func() {
		for {
			pids, err := getParcaGPUPIDs()
			if err != nil {
				log.Errorf("Error getting parcagpu PIDs: %w", err)
			} else {
				for _, pid := range pids {
					pidChan <- pid
				}
			}
			time.Sleep(10 * time.Second)
		}
	}()
	go func() {
		readers := make(map[libpf.PID]*parcaGpuReader)
		attachedDsos := make(map[deviceAndInode]link.Link)
		for {
			select {
			case pid := <-pidChan:
				fmt.Printf("[btv] parcagpu: got new pid: %d\n", pid)
				if _, ok := readers[pid]; ok {
					continue
				}
				ctx, cancel := context.WithCancel(context.TODO())
				rdr, err := handleParcaGpu(ctx, cancel, traceOutChan, attachedDsos, pid, prog)
				if err != nil {
					log.Warnf("Error handling parcagpu: %v", err)
					continue
				}
				if rdr != nil {
					readers[pid] = rdr
				} else {
					log.Debugf("Already attached to this instance of libparcagpu.so")
				}
			case trace := <-traceInChan:
				rdr, ok := readers[trace.PID]
				if !ok {
					log.Warnf("trace for unknown parcagpu PID: %d", trace.PID)
					continue
				}
				rdr.traceInChan <- trace
			}
		}
	}()

	return nil
}
