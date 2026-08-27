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
 * `http.trustProxy` is handed to Express's `trust proxy`, which decides whether
 * `X-Forwarded-For` may rewrite `req.ip` and `X-Forwarded-Proto` may rewrite
 * `req.protocol`. It used to be a boolean, so the only way to accept forwarded
 * headers at all was to accept them from anyone who could reach the process
 * (#292). These tests pin the widened vocabulary and, just as importantly, that
 * a typo fails at boot rather than becoming a policy that never matches.
 */
function configWithTrustProxy(trustProxy: unknown) {
	const config = makeValidCoreConfig() as unknown as Record<string, unknown>;
	const http = config.http as Record<string, unknown>;
	http.trustProxy = trustProxy;
	return config;
}

const parsed = (trustProxy: unknown) =>
	CoreConfigSchema.safeParse(configWithTrustProxy(trustProxy));

describe("http.trustProxy — boolean", () => {
	it.each([false, true])("accepts the boolean %s unchanged", (value) => {
		const result = parsed(value);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toBe(value);
	});

	it.each([
		["true", true],
		["false", false],
	])("coerces the env-var string %s to a boolean", (raw, expected) => {
		// HOCON substitutes `${?HTTP_TRUST_PROXY}` as a string; the only reason
		// `z.boolean()` used to work is that `@o3co/ts.hocon`'s zod bridge
		// coerces for a bare boolean leaf. A union has no such bridge, so the
		// schema has to do it.
		const result = parsed(raw);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toBe(expected);
	});

	it("treats an exported-but-empty env var as `false` rather than as a policy", () => {
		// `HTTP_TRUST_PROXY=` in a .env file, a compose `environment:` entry, or
		// a blank ConfigMap key arrives as "". Fail closed: trust nothing.
		const result = parsed("");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toBe(false);
	});
});

describe("http.trustProxy — hop count", () => {
	it.each([0, 1, 3])("accepts the hop count %s", (value) => {
		const result = parsed(value);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toBe(value);
	});

	it("coerces a numeric env-var string to a number, not to a one-entry address list", () => {
		const result = parsed("2");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toBe(2);
	});

	it("rejects a negative hop count", () => {
		expect(parsed(-1).success).toBe(false);
	});

	it("rejects a fractional hop count", () => {
		expect(parsed(1.5).success).toBe(false);
	});

	it("rejects an absurd hop count as the typo it is", () => {
		// No HTTP path has 100000 proxies in front of it. An operator meaning
		// "trust everything" writes `true` and owns that decision explicitly.
		expect(parsed(100_000).success).toBe(false);
	});
});

describe("http.trustProxy — address list", () => {
	it("accepts a list of IP literals", () => {
		const result = parsed(["10.0.0.7", "2001:db8::1"]);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toEqual(["10.0.0.7", "2001:db8::1"]);
	});

	it("accepts CIDR ranges — the shape an operator with a pod network actually has", () => {
		const result = parsed(["10.0.0.0/8", "fc00::/7"]);
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toEqual(["10.0.0.0/8", "fc00::/7"]);
	});

	it.each(["loopback", "linklocal", "uniquelocal"])(
		"accepts the Express named range %s",
		(name) => {
			const result = parsed([name]);
			expect(result.success).toBe(true);
		},
	);

	it("splits a comma-separated env-var string into entries", () => {
		// The only override surface is `${?HTTP_TRUST_PROXY}`, and HOCON
		// substitutes it as a scalar string. Without this an operator could not
		// configure a list at all without editing a .conf file.
		const result = parsed("10.0.0.0/8, 192.168.0.0/16");
		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data.http.trustProxy).toEqual(["10.0.0.0/8", "192.168.0.0/16"]);
		}
	});

	it("accepts a single-entry string", () => {
		const result = parsed("loopback");
		expect(result.success).toBe(true);
		if (result.success) expect(result.data.http.trustProxy).toEqual(["loopback"]);
	});

	it("rejects an empty list — a policy that matches nothing is a mistake, not a setting", () => {
		// `false` is how a deployment says "trust no forwarding hop". An empty
		// list reads as a list someone meant to fill in.
		expect(parsed([]).success).toBe(false);
	});

	it("rejects a hostname entry at boot rather than never matching it", () => {
		const result = parsed(["proxy.internal"]);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.join(".") === "http.trustProxy.0")).toBe(true);
		}
	});

	it("names the offending index so a long list is diagnosable", () => {
		const result = parsed(["loopback", "10.0.0.0/8", "10.0.0.0/33"]);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => i.path.join(".") === "http.trustProxy.2")).toBe(true);
		}
	});

	it("rejects dotted-netmask notation with a message naming the prefix-length form", () => {
		const result = parsed(["10.0.0.0/255.0.0.0"]);
		expect(result.success).toBe(false);
		if (!result.success) {
			expect(result.error.issues.some((i) => /prefix length/i.test(i.message))).toBe(true);
		}
	});

	it("rejects a non-string entry", () => {
		expect(parsed([42]).success).toBe(false);
	});
});

describe("http.trustProxy — unusable shapes", () => {
	it.each([null, {}])("rejects %s", (value) => {
		expect(parsed(value).success).toBe(false);
	});

	it("is required — boot fails when the key is absent", () => {
		const config = makeValidCoreConfig() as unknown as Record<string, unknown>;
		const http = config.http as Record<string, unknown>;
		delete http.trustProxy;
		expect(CoreConfigSchema.safeParse(config).success).toBe(false);
	});
});
