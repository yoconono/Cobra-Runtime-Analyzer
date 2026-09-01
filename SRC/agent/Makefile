VERSION ?= 0.1.9
GOARCH  ?= amd64
BIN      = ../build/cobraagent

.PHONY: build vet test deb clean

build: vet
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build \
		-trimpath -ldflags "-s -w -X main.version=$(VERSION)" \
		-o $(BIN) ./

vet:
	go vet ./...

test:
	go test ./...

# Requires nfpm (https://nfpm.goreleaser.com)
deb: build
	cd packaging && VERSION=$(VERSION) GOARCH=$(GOARCH) \
		nfpm pkg --packager deb --target ../../build/

clean:
	rm -f $(BIN) ../build/*.deb
