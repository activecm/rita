VERSION := $(shell git describe --always --abbrev=0 --tags)

LDFLAGS := -ldflags='-X main.Version=$(VERSION) -extldflags "-static"'
CGO_ENABLED ?= 0
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)

.PHONY: build test test-unit test-integration test-database test-cmd test-viewer test-lab compose-lab-config lab-up lab-down clean

build:
	CGO_ENABLED=$(CGO_ENABLED) GOARCH=$(GOARCH) GOOS=$(GOOS) go build $(LDFLAGS) -o rita

test: test-unit test-integration test-database test-cmd test-viewer

test-unit:
	go test --cover $$(go list ./... | grep -v /integration | grep -v /database | grep -v /cmd | grep -v /viewer)

test-integration:
	go test ./integration/... -timeout 1800s

test-database:
	go test ./database/... -timeout 1800s

test-cmd:
	go test ./cmd/... -timeout 1800s

test-viewer:
	go test ./viewer/... -timeout 1800s

test-lab:
	go test ./lab/...

compose-lab-config:
	docker compose -f docker-compose.lab.yml config

lab-up:
	docker compose -f docker-compose.lab.yml up --build --abort-on-container-exit

lab-down:
	docker compose -f docker-compose.lab.yml down --volumes

clean:
	rm -f rita
