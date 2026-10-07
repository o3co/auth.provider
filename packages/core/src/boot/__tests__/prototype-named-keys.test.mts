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
 * A configuration key named after an `Object.prototype` member, or
 * `prototype`, refuses boot at its one parse, naming the key's full path. The HOCON loader keeps such a
 * key as an own key; a schema would drop it (`__proto__` in a record or a
 * passthrough object) or keep a name the code reads as an inherited member.
 */

import { parseString } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import type { BootstrapMap } from "#/boot/types.mjs";
import { BootError } from "#/boot/types.mjs";
import { validateManifests } from "#/boot/validate-manifests.mjs";
import type { Module } from "#/modules/manifest/index.mjs";
import { memoryRateLimiterModule } from "#/ratelimit/module.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

/** The configuration as a composition root hands it over: HOCON, loaded, never parsed. */
const loaded = (hocon: string): Record<string, unknown> =>
	parseString(hocon).toObject() as Record<string, unknown>;

/** Core's valid sections with `extra` laid over the top level, as written. */
const resolved = (extra: Record<string, unknown>): Record<string, unknown> => {
	const base = makeValidCoreConfig() as unknown as Record<string, unknown>;
	return { ...base, ...extra };
};

/** What boot's one parse refused with, or a failure when it accepted the configuration. */
function refusal(modules: readonly Module[], config: Record<string, unknown>): BootError {
	try {
		validateManifests({
			modules,
			bootstrapComponents: {
				config: config as never,
				pathResolver: (s: string) => s,
			} satisfies Record<string, unknown> as BootstrapMap,
		});
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

/** The rate limiter's own section, with `limits` as the operator wrote it over the shipped keys. */
const limiterSection = (limits: string) =>
	loaded(
		`"core-rate-limiter-memory" { maxBuckets = 10000, defaultLimit { limit = 60, windowSeconds = 60 }, limits { ${limits} } }`,
	);

describe("a configuration key named after an Object.prototype member, or prototype, refuses boot", () => {
	it.each(["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf"])(
		"a rate-limit `limits` entry named %s, naming its path",
		(name) => {
			const config = resolved({
				core: { ...(makeValidCoreConfig().core as object), deployment: { mode: "single" } },
				...limiterSection(
					`"${name}" { limit = 1, windowSeconds = 60 }, ok { limit = 2, windowSeconds = 60 }`,
				),
			});

			const err = refusal([memoryRateLimiterModule], config);

			expect(err.reason).toBe("config-validation-failed");
			expect(err.stage).toBe("validateManifests");
			expect(err.message).toContain(`core-rate-limiter-memory.limits.${name}`);
			expect(err.details).toMatchObject({
				reason: "config-validation-failed",
				issues: [expect.objectContaining({ path: ["core-rate-limiter-memory", "limits", name] })],
			});
		},
	);

	it("a federation named __proto__ in core.federations, naming its path", () => {
		const core = makeValidCoreConfig().core as Record<string, unknown>;
		const federations = loaded(`__proto__ { enabled = true, type = acme }`);

		const err = refusal([], resolved({ core: { ...core, federations } }));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core.federations.__proto__");
	});

	it("a key named __proto__ inside a federation entry, naming its path", () => {
		const core = makeValidCoreConfig().core as Record<string, unknown>;
		const federations = loaded(`corp { enabled = false, type = acme, __proto__ { issuer = x } }`);

		const err = refusal([], resolved({ core: { ...core, federations } }));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("core.federations.corp.__proto__");
	});

	it("a key in a list's object, in a section nothing owns, naming its path with the index", () => {
		const err = refusal([], resolved(loaded(`extra = [ { id = a }, { __proto__ = b } ]`)));

		expect(err.reason).toBe("config-validation-failed");
		expect(err.message).toContain("extra.1.__proto__");
	});

	it("says which reserved group each key is in", () => {
		const err = refusal([], resolved(loaded(`extra { prototype = 1, toString = 2 }`)));

		expect(err.message).toContain(
			'extra.prototype: the key "prototype" is "prototype", which configuration cannot carry',
		);
		expect(err.message).toContain(
			'extra.toString: the key "toString" is named after an Object.prototype member',
		);
	});

	it("names a key under every path that reaches it when one object is shared", () => {
		const shared = loaded(`__proto__ = x`);

		const err = refusal([], resolved({ first: { at: shared }, second: { at: shared } }));

		expect(err.message).toContain("first.at.__proto__");
		expect(err.message).toContain("second.at.__proto__");
	});

	it("names every such key in one refusal", () => {
		const core = makeValidCoreConfig().core as Record<string, unknown>;
		const err = refusal(
			[],
			resolved({
				core: { ...core, federations: loaded(`constructor { enabled = false, type = oidc }`) },
				...loaded(`extra { toString = 1 }`),
			}),
		);

		expect(err.message).toContain("core.federations.constructor");
		expect(err.message).toContain("extra.toString");
	});

	it("accepts the same sections with no such key", () => {
		const config = resolved({
			core: { ...(makeValidCoreConfig().core as object), deployment: { mode: "single" } },
			...limiterSection(`ok { limit = 2, windowSeconds = 60 }`),
			...loaded(`extra = [ { id = a } ]`),
		});

		expect(() =>
			validateManifests({
				modules: [memoryRateLimiterModule],
				bootstrapComponents: {
					config: config as never,
					pathResolver: (s: string) => s,
				} satisfies Record<string, unknown> as BootstrapMap,
			}),
		).not.toThrow();
	});
});
