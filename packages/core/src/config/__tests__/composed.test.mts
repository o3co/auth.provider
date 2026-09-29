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
 * The transitional base of boot's one composed parse (#728), and the reader a
 * composition root uses before it knows its modules: core's own sections and
 * every section core's schema still mirrors for a package, each optional,
 * with the coercions they always had — laid over what was written, so a key
 * no schema declares is kept.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { AppConfigSchema } from "../application.schema.mjs";
import { overlayConfig, readTransitionalConfig, TransitionalConfigSchema } from "../composed.mjs";

/** A resolved configuration: core's sections, plus whatever `extra` adds at the top. */
const resolved = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
	...makeValidCoreConfig(),
	...extra,
});

/** `value` frozen all the way down, so a change to it throws. */
function deepFreeze<T>(value: T): T {
	if (typeof value === "object" && value !== null) {
		for (const child of Object.values(value)) deepFreeze(child);
		Object.freeze(value);
	}
	return value;
}

describe("TransitionalConfigSchema — core's sections, and every mirrored one optional", () => {
	it("requires none of the sections core mirrors for another package", () => {
		expect(TransitionalConfigSchema.safeParse(resolved()).success).toBe(true);
		// The schema a composition root pre-parsed with requires six of them.
		expect(AppConfigSchema.safeParse(resolved()).success).toBe(false);
	});

	it("declares every section AppConfigSchema declares, with the same schema", () => {
		expect(Object.keys(TransitionalConfigSchema.shape).sort()).toEqual(
			Object.keys(AppConfigSchema.shape).sort(),
		);
	});
});

describe("readTransitionalConfig — the switches a composition root reads before its modules", () => {
	it("reads an environment variable's string as the value its section's schema makes of it", () => {
		const config = readTransitionalConfig(
			resolved({
				http: { port: "8080", trustProxy: "false", readinessTimeoutMs: "1500" },
				redisRateLimiter: { limits: { token: { limit: "120", windowSeconds: "60" } } },
			}),
		);
		expect(config.http.port).toBe(8080);
		expect(config.http.readinessTimeoutMs).toBe(1500);
		expect(config.redisRateLimiter?.limits?.token).toEqual({ limit: 120, windowSeconds: 60 });
	});

	it("keeps what no schema declares, at the top and under a section core declares", () => {
		const config = readTransitionalConfig(
			resolved({
				widget: { size: "3" },
				oauth: { ...makeValidCoreConfig().oauth, fixtureWidget: { enabled: "true" } },
			}),
		) as unknown as { widget: unknown; oauth: { fixtureWidget: unknown } };
		expect(config.widget).toEqual({ size: "3" });
		expect(config.oauth.fixtureWidget).toEqual({ enabled: "true" });
	});

	it("refuses a value a section's schema refuses, naming each path the operator wrote", () => {
		let thrown: unknown;
		try {
			readTransitionalConfig(
				resolved({
					http: { port: "not-a-port", trustProxy: false, readinessTimeoutMs: 1000 },
					deployment: { mode: "several" },
				}),
			);
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(RangeError);
		expect((thrown as Error).message).toMatch(/http\.port: /);
		expect((thrown as Error).message).toMatch(/deployment\.mode: /);
		expect((thrown as Error).cause).toBeInstanceOf(z.ZodError);
	});

	it("changes nothing it was given", () => {
		const given = deepFreeze(resolved({ widget: { size: "3" }, deployment: { mode: "single" } }));
		const before = JSON.stringify(given);
		expect(() => readTransitionalConfig(given)).not.toThrow();
		expect(JSON.stringify(given)).toBe(before);
	});
});

describe("overlayConfig — a parse laid over what was written", () => {
	it("merges objects key by key, the upper value winning, a key only the lower has kept", () => {
		expect(
			overlayConfig(
				{ a: { kept: 1, both: "raw" }, list: [1, 2, 3] },
				{ a: { both: 2 }, list: [9] },
			),
		).toEqual({ a: { kept: 1, both: 2 }, list: [9] });
	});

	it("leaves the lower value where the upper one is undefined", () => {
		expect(overlayConfig({ a: 1 }, { a: undefined })).toEqual({ a: 1 });
		expect(overlayConfig({ a: 1 }, undefined)).toEqual({ a: 1 });
	});

	it("takes a value that is not a plain object whole", () => {
		const url = new URL("https://idp.example/");
		expect(overlayConfig({ a: { href: "x" } }, { a: url })).toEqual({ a: url });
		expect((overlayConfig({ a: { href: "x" } }, { a: url }) as { a: unknown }).a).toBe(url);
	});

	it("keeps a key named __proto__ as a key", () => {
		const lower = JSON.parse('{"__proto__": {"polluted": true}}') as Record<string, unknown>;
		const merged = overlayConfig(lower, { a: 1 }) as Record<string, unknown>;
		expect(Object.hasOwn(merged, "__proto__")).toBe(true);
		expect(({} as Record<string, unknown>).polluted).toBeUndefined();
	});
});
