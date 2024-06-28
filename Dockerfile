FROM --platform=$BUILDPLATFORM golang:1.22-alpine as rita-builder

ARG TARGETOS
ARG TARGETARCH

# install dependencies
RUN apk add --no-cache git make ca-certificates wget build-base

# set the working directory
WORKDIR /go/src/github.com/activecm/rita

# cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# copy the rest of the code
COPY . ./

# Change ARGs with --build-arg to target other architectures
# Produce a self-contained statically linked binary
ARG CGO_ENABLED=0

# Set the build target architecture and OS
ARG GOARCH=${TARGETARCH}
ARG GOOS=${TARGETOS}
# Passing arguments in to make result in them being set as
# environment variables for the call to go build
RUN make CGO_ENABLED=$CGO_ENABLED GOARCH=$GOARCH GOOS=$GOOS
# RUN mkdir /var/log/rita
# RUN chmod 0755 /var/log/rita

FROM alpine

# RUN mkdir /logs
# RUN chmod 0755 /logs

WORKDIR /
# COPY --from=rita-builder /go/src/github.com/activecm/rita/config.hjson /etc/rita/config.hjson
COPY --from=rita-builder /go/src/github.com/activecm/rita/rita /rita
# COPY --from=rita-builder /go/src/github.com/activecm/rita/.env.production /.env
# COPY --from=rita-builder /go/src/github.com/activecm/rita/deployment /etc/rita

ENTRYPOINT ["/rita"]