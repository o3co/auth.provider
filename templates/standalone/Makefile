.PHONY: dev test build

dev:
	docker compose up --build

test:
	docker compose -f docker-compose.test.yml up --build --abort-on-container-exit --exit-code-from test

build:
	docker build --target runtime -t auth-provider .
