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

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// CubinFileSource reopens an application's original, standalone cubin. It owns
// neither a file descriptor nor code bytes. Reads validate content as well as
// file metadata, including writes within one filesystem timestamp tick.
type CubinFileSource struct {
	pid    uint32
	path   string // Relative to the target process's root, for process.Open.
	stat   syscall.Stat_t
	hashes [][sha256.Size]byte // 32 bytes per 4 KiB, not instruction bytes.
}

const cubinBlockSize = 4096

// MatchCubinFile accepts a provenance hint only after comparing the entire raw
// image, not just the sampled FileID or CUPTI CRC. PTX, fatbins and shared
// libraries are not standalone loaded images and will not match.
func MatchCubinFile(pid uint32, path string, data []byte) (*CubinFileSource, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("cubin path is not absolute")
	}
	s := &CubinFileSource{pid: pid, path: strings.TrimPrefix(path, "/")}
	f, err := s.openFile()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := syscall.Fstat(int(f.Fd()), &s.stat); err != nil {
		return nil, err
	}
	if s.stat.Size != int64(len(data)) {
		return nil, errors.New("cubin file size does not match loaded image")
	}
	s.hashes = make([][sha256.Size]byte, (len(data)+cubinBlockSize-1)/cubinBlockSize)
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
	if err := s.check(f); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *CubinFileSource) openFile() (*os.File, error) {
	// Process.Open uses openat2 RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	// including regular-file checks. Never resolve a container path on the host.
	f, err := process.New(libpf.PID(s.pid), libpf.PID(s.pid)).Open(s.path)
	if err != nil {
		return nil, err
	}
	return f.(*os.File), nil
}

func (s *CubinFileSource) check(f *os.File) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	// Ignore atime, which our reads can change. Block hashes below also detect
	// same-timestamp writes, so metadata is only a fast rejection path.
	if st.Dev != s.stat.Dev || st.Ino != s.stat.Ino || st.Size != s.stat.Size ||
		st.Mtim != s.stat.Mtim || st.Ctim != s.stat.Ctim {
		return errors.New("original cubin file changed")
	}
	return nil
}

func (s *CubinFileSource) open() (*checkedCubinFile, error) {
	f, err := s.openFile()
	if err != nil {
		return nil, err
	}
	if err := s.check(f); err != nil {
		f.Close()
		return nil, err
	}
	return &checkedCubinFile{File: f, source: s}, nil
}

type checkedCubinFile struct {
	*os.File
	source *CubinFileSource
	// held marks a descriptor opened while the process was alive. Unlinking
	// or renaming the path changes ctime, so only block hashes validate it.
	held bool
}

func (f *checkedCubinFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative cubin offset")
	}
	if !f.held {
		if err := f.source.check(f.File); err != nil {
			return 0, err
		}
	}
	var block [cubinBlockSize]byte
	n := 0
	for n < len(p) && off < f.source.stat.Size {
		start := off / cubinBlockSize * cubinBlockSize
		size := min(int64(cubinBlockSize), f.source.stat.Size-start)
		if _, err := f.File.ReadAt(block[:size], start); err != nil {
			// Blocks lie within the matched size, so EOF means truncation,
			// which io.Copy would otherwise accept as a complete image.
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return n, err
		}
		if sha256.Sum256(block[:size]) != f.source.hashes[start/cubinBlockSize] {
			return n, errors.New("original cubin content changed")
		}
		copied := copy(p[n:], block[off-start:size])
		n += copied
		off += int64(copied)
	}
	if !f.held {
		if checkErr := f.source.check(f.File); checkErr != nil {
			return 0, checkErr
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (s *CubinFileSource) ReadAt(p []byte, off int64) (int, error) {
	f, err := s.open()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.ReadAt(p, off)
}

// UploadProcess returns an upload adapter that holds the original file open,
// so a queued upload still reads it after the process exits, its mount
// namespace goes away or the file is unlinked. The descriptor closes when the
// uploader drops the adapter and the *os.File is garbage collected; it retains
// no code bytes. If the file cannot be opened now, the adapter falls back to
// image, the bytes read from process memory, as legacy uploads do.
func (s *CubinFileSource) UploadProcess(image []byte) process.Process {
	f, err := s.open()
	if err != nil {
		log.Warnf("[cuda] original cubin %s of pid %d unavailable for upload, using process memory: %v",
			s.path, s.pid, err)
		return NewCubinProcess(s.pid, image)
	}
	return &cubinProcess{pid: s.pid, source: s, file: f.File}
}
