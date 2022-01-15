deps:
	if ! [ -f $(shell which go) ] ; then \
	sudo apt update && \
	sudo apt install golang-1.16 && \
	sudo update-alternatives --install /usr/bin/go go /usr/lib/go-1.16/bin/go 10; \
	fi

build: deps
	go build

wasm-build: deps
	GOOS=js GOARCH=wasm go build -o verify.wasm verify.go

wasm-test: wasm-build
	cp $(shell go env GOROOT)/misc/wasm/wasm_exec.js .
	go test
