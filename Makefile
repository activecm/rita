VERSION := $(shell git describe --always --abbrev=0 --tags)

LDFLAGS := -ldflags='-X main.Version=$(VERSION) -extldflags "-static"'
CGO_ENABLED ?= 0
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)

.PHONY: rita
rita:
	CGO_ENABLED=$(CGO_ENABLED) GOARCH=$(GOARCH) GOOS=$(GOOS) go build $(LDFLAGS) -o rita