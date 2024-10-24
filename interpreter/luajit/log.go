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

package luajit

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

var development bool

func init() {
	_, dbgEnv := os.LookupEnv("LUA_DEBUG")
	ex, _ := os.Executable()
	goRun := strings.Contains(filepath.Dir(ex), "go-build")
	dlvRun := strings.HasPrefix(filepath.Base(ex), "__debug_bin")
	development = (goRun || dlvRun) && dbgEnv
}

// During development logf as higher level so they stick out w/o enabling debug firehose.
func logf(format string, args ...interface{}) {
	if development {
		logrus.Infof(format, args...)
	} else {
		logrus.Debugf(format, args...)
	}
}
