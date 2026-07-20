.PHONY: test check build-linux

test:
	go test ./...

check: test
	go vet ./...
	bash -n installer.sh
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/chr-install-linux-amd64 ./cmd/chr-install

build-linux:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/chr-install-linux-amd64 ./cmd/chr-install
