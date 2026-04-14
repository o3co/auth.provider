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
	pnpm -r exec rimraf dist

.PHONY: test
test:
	pnpm -r run test
