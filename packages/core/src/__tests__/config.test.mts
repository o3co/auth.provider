import { parseFile } from "@o3co/ts.hocon";
import { validate } from "@o3co/ts.hocon/zod";
import { describe, expect, it } from "vitest";
import { AppConfigSchema } from "#/config/application.schema.mjs";

describe("provider config", () => {
	it("loads and validates application.conf with required env vars", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.oauth.jwt.secret).toBe("test-secret");
		expect(config.session.secret).toBe("test-session-secret");
		expect(config.http.port).toBe(3000);
		expect(config.oauth.grants.did.messageMaxAgeSec).toBe(300);
	});

	it("fails validation when required fields are missing", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {},
		});
		expect(() => validate(raw, AppConfigSchema)).toThrow();
	});

	it("overrides defaults with env vars", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_APP_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
				HTTP_PORT: "9090",
				OAUTH_GRANTS_DID_ENABLED: "false",
			},
		});
		const config = validate(raw, AppConfigSchema);

		expect(config.http.port).toBe(9090);
		expect(config.oauth.grants.did.enabled).toBe(false);
	});

	it("clients.client.type defaults to yaml", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.client.type).toBe("yaml");
	});

	it("clients.user.type defaults to http", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.user.type).toBe("http");
	});

	it("clients.code.type defaults to redis", () => {
		const raw = parseFile(new URL("../../config/application.conf", import.meta.url).pathname, {
			env: {
				OAUTH_JWT_SECRET: "test-secret",
				SESSION_SECRET: "test-session-secret",
				CLIENT_USER_BASE_URL: "http://localhost:8080",
				CLIENT_CODE_ENDPOINT_URI: "redis://localhost:6379",
			},
		});
		const config = validate(raw, AppConfigSchema);
		expect(config.clients.code.type).toBe("redis");
	});
});
