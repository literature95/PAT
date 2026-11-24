GO ?= go
BIN := bin/pat.exe
PS := powershell -NoProfile -ExecutionPolicy Bypass

.PHONY: build test test-race vet install clean demo demo-nl

build:
	$(GO) build -o $(BIN) ./cmd/pat

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

install: build
	$(PS) -File install.ps1 -BuildFrom "$(CURDIR)"

clean:
	$(PS) -Command "Remove-Item -Recurse -Force bin -ErrorAction SilentlyContinue"

demo: build
	./bin/pat.exe -c "/help"

demo-nl: build
	./bin/pat.exe -c "扫一下 192.168.56.10 的 445"
