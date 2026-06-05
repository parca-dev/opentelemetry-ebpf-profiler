// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/peterbourgon/ff/v3/ffcli"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type uploadCmd struct {
	store *modulestore.Store

	// User-specified command line arguments.
	path string
	all  bool
	gcs  bool
}

func newUploadCmd(store *modulestore.Store) *ffcli.Command {
	cmd := uploadCmd{store: store}
	set := flag.NewFlagSet("upload", flag.ExitOnError)
	set.StringVar(&cmd.path, "path", "", "The path to a specific test case JSON")
	set.BoolVar(&cmd.all, "all", false, "Upload all referenced modules for all test cases")
	set.BoolVar(&cmd.gcs, "gcs", false,
		"Upload to the public GCS bucket instead of the default remote storage")
	return &ffcli.Command{
		Name:       "upload",
		ShortUsage: "upload [flags]",
		ShortHelp:  "Upload a test case to the remote storage",
		FlagSet:    set,
		Exec:       cmd.exec,
	}
}

func (cmd *uploadCmd) exec(context.Context, []string) (err error) {
	if (cmd.all && cmd.path != "") || (!cmd.all && cmd.path == "") {
		return errors.New("please pass either `-path` or `-all` (but not both)")
	}

	if cmd.gcs {
		if cloudstore.GCSBucket() == "" {
			return fmt.Errorf("the -gcs flag requires the %s environment variable to be set",
				cloudstore.GCSBucketEnvVar)
		}
		gcsClient, gerr := cloudstore.GCSClient()
		if gerr != nil {
			return fmt.Errorf("failed to create GCS client: %w", gerr)
		}
		cmd.store, err = modulestore.New(gcsClient,
			cloudstore.GCSPublicReadURL(), cloudstore.GCSBucket(), "modulecache")
		if err != nil {
			return fmt.Errorf("failed to create GCS module store: %w", err)
		}
	}

	var paths []string
	if cmd.all {
		paths, err = findTestCases(false)
		if err != nil {
			return errors.New("failed to scan for test cases")
		}
	} else {
		paths = []string{cmd.path}
	}

	var modules []modulestore.ID //nolint:prealloc
	for _, testCase := range paths {
		var test *CoredumpTestCase
		test, err = readTestCase(testCase)
		if err != nil {
			return fmt.Errorf("failed to read test case: %w", err)
		}

		modules = append(modules, test.CoredumpRef)
		for _, x := range test.Modules {
			modules = append(modules, x.Ref)
		}
	}

	// We retrieve the remote module list to prevent polling the status for
	// each module individually.
	remoteModules, err := cmd.store.ListRemoteModules()
	if err != nil {
		return fmt.Errorf("failed to retrieve remote module list: %w", err)
	}

	for _, id := range modules {
		if _, present := remoteModules[id]; present {
			continue
		}

		log.Infof("Uploading module `%s`", id.String())
		if err = cmd.store.UploadModule(id); err != nil {
			return fmt.Errorf("failed to upload module: %w", err)
		}
	}

	log.Info("All modules are present remotely")
	return nil
}
