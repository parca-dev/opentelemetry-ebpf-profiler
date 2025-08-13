// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package customlabels_test

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"

	"time"

	"github.com/stretchr/testify/require"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type symbolMap map[libpf.FrameID]string

type testLogConsumer struct {
	t *testing.T
}

func (tlc *testLogConsumer) Accept(l testcontainers.Log) {
	tlc.t.Logf("[%s] %s", l.LogType, string(l.Content))
}

const N_WORKERS int = 8

var files = []string{
	"AUTHORS.md",
	"CODE_OF_CONDUCT.md",
	"CONTRIBUTING.md",
	"INDEX.md",
	"PUBLISHING.md",
	"USING_ADVANCED.md",
	"USING_PRO.md",
	"broken.md",
}

func TestIntegration(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	for _, nodeVersion := range []string{
		"24.5.0",
		"22.18.0",
		"20.19.4",
	} {
		name := fmt.Sprintf("node-v%s", nodeVersion)
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			defer cancel()

			cont := startContainer(ctx, t, nodeVersion)

			enabledTracers, err := tracertypes.Parse("labels,v8")
			require.NoError(t, err)

			r := &mockReporter{symbols: make(symbolMap)}
			traceCh, trc := testutils.StartTracer(ctx, t, enabledTracers, r)

			testHTTPEndpoint(ctx, t, cont)
			framesPerWorkerId := make(map[int]int)
			framesPerFileName := make(map[string]int)

			totalWorkloadFrames := 0
			unlabeledWorkloadFrames := 0

			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()

			for {
				select {
				case <-timer.C:
					goto done
				case trace := <-traceCh:
					if trace == nil {
						continue
					}
					ct, err := trc.TraceProcessor().ConvertTrace(trace)
					require.NotNil(t, ct)
					require.NoError(t, err)
					workerId, okWid := trace.CustomLabels["workerId"]
					filePath, okFname := trace.CustomLabels["filePath"]
					var fileName string
					if okFname {
						fileName = path.Base(filePath)
					}
					knownWorkloadFrames := []string{
						"lex",
						"parse",
						"blockTokens",
						"readFile",
						"readFileHandle",
					}
					hasWorkloadFrame := false
					for i, _ := range ct.FrameTypes {
						if ct.FrameTypes[i] == libpf.V8Frame {
							id := libpf.NewFrameID(ct.Files[i], ct.Linenos[i])
							name := r.getFunctionName(id)
							if slices.Contains(knownWorkloadFrames, name) {
								hasWorkloadFrame = true
							}
						}
					}

					if hasWorkloadFrame {
						totalWorkloadFrames++
						if !(okWid && okFname) {
							unlabeledWorkloadFrames++
						}
					}

					if okWid {
						val, err := strconv.Atoi(workerId)
						require.NoError(t, err)

						require.GreaterOrEqual(t, val, 0)
						require.Less(t, val, N_WORKERS)

						framesPerWorkerId[val]++
					}

					if okFname {
						require.Contains(t, files, fileName)
						framesPerFileName[fileName]++
					}
				}
			}
		done:
			totalWidFrames := 0
			// for 8 workers, each should have roughly 1/8
			// of the labeled frames. Accept anything above 75% of that.
			for i := 0; i < N_WORKERS; i++ {
				totalWidFrames += framesPerWorkerId[i]
			}
			expectedWorkerAvg := float64(totalWidFrames)/float64(N_WORKERS)
			for i := 0; i < N_WORKERS; i++ {
				require.Less(t, expectedWorkerAvg * 0.75, float64(framesPerWorkerId[i]))
			}
			// Each of the documents should account for some nontrivial amount of time,
			// but since they aren't all the same length, we are less strict.
			totalFnameFrames := 0
			for _, v := range(framesPerFileName) {
				totalFnameFrames += v
			}
			expectedFnameAvg := float64(totalFnameFrames) / float64(len(framesPerFileName))
			for _, v:= range(framesPerFileName) {
				require.Less(t, expectedFnameAvg * 0.2, float64(v))
			}

			// Really, there should be zero frames in the `marked` workload
			// that aren't under labels, but accept a 1% slop because the unwinder isn't perfect (e.g. it might
			// interrupt the process when the Node environment is in an undefined state)
			require.Less(t, 100 * unlabeledWorkloadFrames, totalWorkloadFrames)
		})
	}
}

func startContainer(ctx context.Context, t *testing.T, nodeVersion string) testcontainers.Container {
	t.Log("starting container for node version", nodeVersion)
	_, path, _, _ := runtime.Caller(0)
	cont, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context: filepath.Dir(path) + "/testdata/node-md-render/",
				BuildArgs: map[string]*string{
					"NODE_VERSION": &nodeVersion,
				},
			},
			ExposedPorts: []string{"80/tcp"},
			LogConsumerCfg: &testcontainers.LogConsumerConfig{
				Consumers: []testcontainers.LogConsumer{&testLogConsumer{t: t}},
			},
			WaitingFor: wait.ForHTTP("/docs/AUTHORS.md"),
		},
		Started: true,
	})
	require.NoError(t, err)
	return cont
}

func testHTTPEndpoint(ctx context.Context, t *testing.T, cont testcontainers.Container) {
	const numGoroutines = 10
	const requestsPerGoroutine = 10000

	host, err := cont.Host(ctx)
	require.NoError(t, err)

	port, err := cont.MappedPort(ctx, "80")
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://%s:%s", host, port.Port())

	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for j := 0; j < requestsPerGoroutine; j++ {
				file := files[rand.Intn(len(files))]
				url := fmt.Sprintf("%s/docs/%s", baseURL, file)

				resp, err := http.Get(url)
				require.NoError(t, err)
				// if we don't read body to completion, the http library will kill the connection
				// instead of reusing it, and we might run out of ports.
				_, err = io.ReadAll(resp.Body)
				require.NoError(t, err)
				err = resp.Body.Close()
				require.NoError(t, err)

				require.Equal(t, http.StatusOK, resp.StatusCode, "Expected status 200 for %s", file)
			}
		}()
	}

	wg.Wait()
}

type mockReporter struct {
	mu      sync.Mutex
	symbols symbolMap
}

var _ reporter.SymbolReporter = &mockReporter{}

func (m *mockReporter) ExecutableMetadata(*reporter.ExecutableMetadataArgs) {
}
func (m *mockReporter) FrameKnown(_ libpf.FrameID) bool { return false }
func (m *mockReporter) ExecutableKnown(libpf.FileID) bool {
	return false
}
func (m *mockReporter) FrameMetadata(args *reporter.FrameMetadataArgs) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.symbols[args.FrameID] = args.FunctionName
}

func (m *mockReporter) getFunctionName(frameID libpf.FrameID) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.symbols[frameID]
}
