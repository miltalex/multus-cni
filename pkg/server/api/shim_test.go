// Copyright (c) 2026 Multus Authors
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

package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

func TestCmdDelReturnsCNIError(t *testing.T) {
	t.Setenv("CNI_COMMAND", "DEL")

	runDir := t.TempDir()
	listener, err := net.Listen("unix", SocketPath(runDir))
	if err != nil {
		t.Fatalf("failed to listen on unix socket: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == MultusHealthAPIEndpoint {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":50,"msg":"DEL failed"}`))
		}),
	}
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("failed to close test server: %v", err)
		}
		if err := <-serveErrCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("test server Serve() failed: %v", err)
		}
	})

	args := &skel.CmdArgs{StdinData: shimTestConfig(runDir)}
	if err := CmdDel(args); err == nil || err.Error() != "CmdDel (shim): DEL failed" {
		t.Fatalf("expected DEL error, got %v", err)
	}
}

func TestCmdDelReturnsReadinessError(t *testing.T) {
	t.Setenv("CNI_COMMAND", "DEL")

	args := &skel.CmdArgs{StdinData: shimTestConfig(t.TempDir())}

	err := CmdDel(args)
	if err == nil {
		t.Fatal("expected DEL readiness error")
	}
	if got := err.Error(); !strings.HasPrefix(got, "CmdDel (shim): CheckAPIReadyNow:") {
		t.Fatalf("expected shim DEL error, got %q", got)
	}
}

func shimTestConfig(runDir string) []byte {
	return []byte(fmt.Sprintf(`{"cniVersion":"0.4.0","daemonSocketDir":%q}`, runDir))
}
