/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/**
 * `oauth.jwt.issuer` is the identity every token this deployment mints is
 * bound to, and the value resource servers pin. It must be a fixed canonical
 * URL supplied by the operator — never derived from a request — so these tests
 * pin what the schema accepts as one.
 */
function configWithIssuer(issuer?: unknown) {
	const config = makeValidCoreConfig() as unknown as Record<string, unknown>;
	const oauth = config.oauth as Record<string, unknown>;
	const jwt = oauth.jwt as Record<string, unknown>;
	if (issuer === undefined) {
		delete jwt.issuer;
	} else {
		jwt.issuer = issuer;
	}
	return config;
}

describe("oauth.jwt.issuer", () => {
	it("is required — boot fails when it is absent", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer());
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.join(".").includes("issuer"))).toBe(true);
		}
	});

	it("accepts an absolute https URL", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer("https://auth.example.com"));
		expect(result.success).toBe(true);
	});

	it("accepts an https URL with a path prefix", () => {
		const result = CoreConfigSchema.safeParse(
			configWithIssuer("https://auth.example.com/tenant-a"),
		);
		expect(result.success).toBe(true);
	});

	it("rejects a bare host — the shape a Host header would have supplied", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer("auth.example.com:3000"));
		expect(result.success).toBe(false);
	});

	it("rejects a non-loopback http URL", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer("http://auth.example.com"));
		expect(result.success).toBe(false);
	});

	it.each(["http://localhost:3000", "http://127.0.0.1:3000", "http://[::1]:3000"])(
		"accepts %s so local development does not need TLS",
		(issuer) => {
			const result = CoreConfigSchema.safeParse(configWithIssuer(issuer));
			expect(result.success).toBe(true);
		},
	);

	it("rejects an issuer carrying a query string", () => {
		const result = CoreConfigSchema.safeParse(
			configWithIssuer("https://auth.example.com?tenant=a"),
		);
		expect(result.success).toBe(false);
	});

	it("rejects an issuer carrying a fragment", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer("https://auth.example.com#a"));
		expect(result.success).toBe(false);
	});

	it("rejects an empty issuer", () => {
		const result = CoreConfigSchema.safeParse(configWithIssuer(""));
		expect(result.success).toBe(false);
	});
});
