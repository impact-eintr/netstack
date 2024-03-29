// Copyright 2018 Google LLC
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

//go:build amd64

package sleep

import "sync/atomic"

// See commit_noasm.go for a description of commitSleep.
func commitSleep(g uintptr, waitingG *uintptr) bool {
	for {
		// Check if the wait was aborted.
		if atomic.LoadUintptr(waitingG) == 0 {
			return false
		}

		// Try to store the G so that wakers know who to wake.
		if atomic.CompareAndSwapUintptr(waitingG, preparingG, g) {
			return true
		}
	}
}
