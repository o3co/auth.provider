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
	rm -rf packages/core/dist packages/foundation/dist templates/standalone/dist create-app/dist

.PHONY: test
test:
	pnpm -r run test
