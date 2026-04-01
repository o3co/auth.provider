DOCKER_IMAGE:=auth-provider

.PHONY: build
build: install
	pnpm -r run build

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
	rm -rf packages/core/dist templates/standalone/dist create-app/dist

.PHONY: test
test:
	pnpm -r run test

.PHONY: docker
docker: docker/runtime

.PHONY: docker/builder
docker/builder:
	docker build . -t ${DOCKER_IMAGE}:builder --target=builder

.PHONY: docker/runtime
docker/runtime:
	docker build . -t ${DOCKER_IMAGE}:latest --target=runtime
