# Reproducible builds: the same tag and Go version give the same bytes.
VERSION ?= dev
GOFLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: build release test lint
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/mig-collector ./cmd/mig-collector

release:
	mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
			-o dist/mig-collector-linux-$$arch ./cmd/mig-collector || exit 1; \
	done
	cd dist && sha256sum mig-collector-linux-* > SHA256SUMS

test:
	go test -race ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	shellcheck -s sh scripts/install.sh
