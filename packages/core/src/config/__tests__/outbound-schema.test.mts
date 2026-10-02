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

/**
 * `core.outbound`, the outbound fetch's section: strict, every leaf readable
 * from an environment variable, each host entry checked at boot, and
 * `reference.conf`'s defaults the ones the reader applies to an absent section.
 */

import { fileURLToPath } from "node:url";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { CoreConfigSchema } from "#/config/application.schema.mjs";
import { outboundPolicyOf } from "#/net/outbound-fetch.mjs";
import { OutboundSectionSchema } from "#/net/outbound-policy.mjs";
import { withOutbound } from "#/testing/outboundFetch.mjs";

const REFERENCE_CONF_PATH = fileURLToPath(
	new URL("../../../config/reference.conf", import.meta.url),
);

const REQUIRED_ENV = {
	OAUTH_JWT_SECRET: "outbound-schema.test.at-least-32-bytes.ok",
	OAUTH_JWT_ISSUER: "https://auth.test",
	SESSION_SECRET: "outbound-schema.test-session.at-least-32-bytes.ok",
};

const issuePaths = (result: { success: boolean; error?: { issues: { path: PropertyKey[] }[] } }) =>
	result.success ? [] : (result.error?.issues ?? []).map((issue) => issue.path.join("."));

const referenceOutbound = (env: Record<string, string> = {}): unknown =>
	(
		parseFile(REFERENCE_CONF_PATH, { env: { ...REQUIRED_ENV, ...env } }).toObject() as {
			core: { outbound: unknown };
		}
	).core.outbound;

describe("core.outbound in core's schema", () => {
	it("is strict: an unknown key is refused and named", () => {
		const result = OutboundSectionSchema.safeParse({ allowHosts: ["rp.example"] });
		expect(result.success).toBe(false);
		expect(JSON.stringify(result.error?.issues)).toContain("allowHosts");
	});

	it("is a key of core's own section", () => {
		const parsed = CoreConfigSchema.shape.core.safeParse(
			withOutbound({}, { deniedHosts: ["rp.example"] }).core,
		);
		expect(parsed.success).toBe(true);
	});

	it("reads each host list from a comma-separated string, as an environment variable carries it", () => {
		const parsed = OutboundSectionSchema.parse({
			allowedHosts: " rp.example, .corp.example ,,",
			deniedHosts: "",
			internalHosts: ["svc.internal"],
		});
		expect(parsed.allowedHosts).toEqual(["rp.example", ".corp.example"]);
		expect(parsed.deniedHosts).toEqual([]);
		expect(parsed.internalHosts).toEqual(["svc.internal"]);
	});

	it("refuses a host entry that is not a bare host, naming its index", () => {
		const result = OutboundSectionSchema.safeParse({
			deniedHosts: ["rp.example", "https://rp.example/"],
		});
		expect(result.success).toBe(false);
		expect(issuePaths(result)).toEqual(["deniedHosts.1"]);
	});

	it("reads the numbers from an environment string, and refuses anything but a positive whole number", () => {
		expect(OutboundSectionSchema.parse({ timeoutMs: " 2500 ", maxResponseBytes: "1024" })).toEqual({
			timeoutMs: 2500,
			maxResponseBytes: 1024,
		});
		for (const bad of ["", "0", "-1", "1.5", "abc", 0, -1, 1.5, null]) {
			expect(issuePaths(OutboundSectionSchema.safeParse({ timeoutMs: bad })), String(bad)).toEqual([
				"timeoutMs",
			]);
			expect(
				issuePaths(OutboundSectionSchema.safeParse({ maxResponseBytes: bad })),
				String(bad),
			).toEqual(["maxResponseBytes"]);
		}
	});

	it('takes egress = "direct" and nothing else', () => {
		expect(OutboundSectionSchema.parse({ egress: "direct" })).toEqual({ egress: "direct" });
		for (const bad of ["", "proxy", "DIRECT", true]) {
			expect(issuePaths(OutboundSectionSchema.safeParse({ egress: bad }))).toEqual(["egress"]);
		}
	});
});

describe("core.outbound in reference.conf", () => {
	it("ships the defaults the reader applies to an absent section, with no egress", () => {
		const shipped = referenceOutbound();
		expect(shipped).toEqual({
			allowedHosts: [],
			deniedHosts: [],
			internalHosts: [],
			timeoutMs: 5000,
			maxResponseBytes: 65536,
		});
		expect(outboundPolicyOf(withOutbound({}, OutboundSectionSchema.parse(shipped)))).toEqual(
			outboundPolicyOf(undefined),
		);
	});

	it("binds each key to the variable named after its path", () => {
		const outbound = referenceOutbound({
			CORE_OUTBOUND_ALLOWED_HOSTS: "a.example,b.example",
			CORE_OUTBOUND_DENIED_HOSTS: "c.example",
			CORE_OUTBOUND_INTERNAL_HOSTS: "localhost",
			CORE_OUTBOUND_TIMEOUT_MS: "1000",
			CORE_OUTBOUND_MAX_RESPONSE_BYTES: "2048",
			CORE_OUTBOUND_EGRESS: "direct",
		});
		expect(OutboundSectionSchema.parse(outbound)).toEqual({
			allowedHosts: ["a.example", "b.example"],
			deniedHosts: ["c.example"],
			internalHosts: ["localhost"],
			timeoutMs: 1000,
			maxResponseBytes: 2048,
			egress: "direct",
		});
	});
});
