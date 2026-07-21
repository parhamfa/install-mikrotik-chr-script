.PHONY: test check fmt-check lint build-linux

test:
	go test ./...

check: test fmt-check lint
	go vet ./...
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/chr-install-linux-amd64 ./cmd/chr-install

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

lint:
	bash -n installer.sh
	shellcheck installer.sh

build-linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/chr-install-linux-amd64 ./cmd/chr-install
