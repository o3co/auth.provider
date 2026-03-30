DOCKER_IMAGE:=auth-provider

.PHONY: build
build: clean install
	pnpm run build

.PHONY: lint
lint:
	pnpm run lint

.PHONY: audit
audit:
	pnpm run audit

.PHONY: install
install:
	pnpm install

.PHONY: clean
clean:
	rm -rf dist

.PHONY: docker
docker: docker/runtime

.PHONY: docker/builder
docker/builder:
	docker build . -t ${DOCKER_IMAGE}:builder --target=builder

.PHONY: docker/runtime
docker/runtime:
	docker build . -t ${DOCKER_IMAGE}:latest --target=runtime
