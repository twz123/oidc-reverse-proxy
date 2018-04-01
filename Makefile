BUILD_DIR=/go/src/github.com/twz123/oidc-reverse-proxy
BUILDER_IMAGE=docker.io/golang:1.10.0-alpine3.7


DOCKER_IMAGE_NAME=quay.io/twz123/oidc-reverse-proxy
DOCKER_IMAGE_TAG=$(shell git describe --tags --always --dirty)

# binaries
DOCKER=docker
DEP=dep

oidc-reverse-proxy: Gopkg.lock $(shell find pkg/ cmd/ -type f -name \*.go -print)
	$(DOCKER) run --rm -e CGO_ENABLED=0 -v "$(shell pwd -P):$(BUILD_DIR):ro" -w "$(BUILD_DIR)" $(BUILDER_IMAGE) \
	go build -o /dev/stdout cmd/oidc-reverse-proxy.go > oidc-reverse-proxy || { rm oidc-reverse-proxy; exit 1; }
	chmod +x oidc-reverse-proxy

Gopkg.lock: Gopkg.toml $(shell find vendor/ -type f -name \*.go -print)
	$(DEP) ensure

clean:
	rm -f oidc-reverse-proxy

.PHONY: dockerize
dockerize: oidc-reverse-proxy Dockerfile
	$(DOCKER) build . -t $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)

.PHONY: publish-docker-image
publish-docker-image: dockerize
	$(DOCKER) push $(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)
