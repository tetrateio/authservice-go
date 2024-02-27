// Copyright 2024 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

func TestWithValues(t *testing.T) {
	var a logr.LogSink = &logrAdapter{}
	a = a.WithValues("one", 1, "two", 2)
	a = a.WithValues("three")

	require.Equal(t, map[string]interface{}{"one": 1, "two": 2, "three": "(MISSING)"}, a.(*logrAdapter).kvs)
}
