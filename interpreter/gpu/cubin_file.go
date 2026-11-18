// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// CubinFileSource reads an application's original, standalone cubin through a
// descriptor opened while the loading process was alive. Holding the inode,
// not the path, keeps instruction lookups and uploads working after the
// process exits, its mount namespace goes away or the path is unlinked or
// replaced. It retains no code bytes: every read is validated against block
// hashes, which also catch in-place writes within one timestamp tick.
type CubinFileSource struct {
	pid    uint32
	path   string // Relative to the target process's root; for logging only.
	file   *os.File
	size   int64
	hashes [][sha256.Size]byte // 32 bytes per 4 KiB, not instruction bytes.
}

const cubinBlockSize = 4096

// MatchCubinFile accepts a provenance hint only after comparing the entire raw
// image, not just the sampled FileID or CUPTI CRC. PTX, fatbins and shared
// libraries are not standalone loaded images and will not match. It must be
// called while pid is alive; the returned source keeps the file open for as
// long as it is reachable.
func MatchCubinFile(pid uint32, path string, data []byte) (*CubinFileSource, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("cubin path is not absolute")
	}
	rel := strings.TrimPrefix(path, "/")
	// Process.Open uses openat2 RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	// including regular-file checks. Never resolve a container path on the host.
	pf, err := process.New(libpf.PID(pid), libpf.PID(pid)).Open(rel)
	if err != nil {
		return nil, err
	}
	f := pf.(*os.File)
	s, err := matchCubinFile(f, data)
	if err != nil {
		f.Close()
		return nil, err
	}
	s.pid, s.path = pid, rel
	return s, nil
}

func matchCubinFile(f *os.File, data []byte) (*CubinFileSource, error) {
	var before syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &before); err != nil {
		return nil, err
	}
	if before.Size != int64(len(data)) {
		return nil, errors.New("cubin file size does not match loaded image")
	}
	s := &CubinFileSource{
		file:   f,
		size:   before.Size,
		hashes: make([][sha256.Size]byte, (len(data)+cubinBlockSize-1)/cubinBlockSize),
	}
	var block [cubinBlockSize]byte
	for off := 0; off < len(data); off += cubinBlockSize {
		n := min(cubinBlockSize, len(data)-off)
		if _, err := f.ReadAt(block[:n], int64(off)); err != nil {
			return nil, err
		}
		hash := sha256.Sum256(data[off : off+n])
		if sha256.Sum256(block[:n]) != hash {
			return nil, errors.New("cubin file does not match loaded image")
		}
		s.hashes[off/cubinBlockSize] = hash
	}
	return s, nil
}

// ReadAt reads the original image, failing if the held inode was written or
// truncated since it was matched.
func (s *CubinFileSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative cubin offset")
	}
	var block [cubinBlockSize]byte
	n := 0
	for n < len(p) && off < s.size {
		start := off / cubinBlockSize * cubinBlockSize
		size := min(int64(cubinBlockSize), s.size-start)
		if _, err := s.file.ReadAt(block[:size], start); err != nil {
			// Blocks lie within the matched size, so EOF means truncation,
			// which io.Copy would otherwise accept as a complete image.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		if sha256.Sum256(block[:size]) != s.hashes[start/cubinBlockSize] {
			return n, errors.New("original cubin content changed")
		}
		copied := copy(p[n:], block[off-start:size])
		n += copied
		off += int64(copied)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// UploadProcess returns an upload adapter that reads the held original file.
func (s *CubinFileSource) UploadProcess() process.Process {
	return &cubinProcess{pid: s.pid, source: s}
}
