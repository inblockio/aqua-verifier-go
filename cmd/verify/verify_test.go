package main

import (
	"net/http"
	"os"
	"os/exec"
	"testing"
)

func TestWasm(t *testing.T) {
	t.Skip("Skipping WASM test for now.")
	// Spawns a http server and browser to test the javascript (wasm) build of verify loads in console
	// TODO: can automate using nodejs using go_js_wasm_exec, e.g.
	// GOOS=js GOARCH=wasm go test -exec="$(go env GOROOT)/misc/wasm/go_js_wasm_exec"
	// TODO: load json into DOM and verify
	s := &http.Server{
		Addr:    ":8080",
		Handler: http.FileServer(http.Dir(`.`)),
	}
	go func() {
		s.ListenAndServe()
	}()

	// launch brower, wait for exit
	b := exec.Command("xdg-open", "http://localhost:8080")
	_, err := b.Output()
	if err != nil {
		t.Errorf(err.Error())
	}
	p := b.Process.Pid
	proc, err := os.FindProcess(p)
	if err == nil {
		proc.Wait()
	}
	s.Close()
}
