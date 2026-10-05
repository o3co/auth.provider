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
 * `readCoreSection`: core's own section, `core {}`, read from a resolved
 * configuration no schema has parsed, by its strict schema alone. A
 * composition root reads it before it knows its modules; every other
 * section is left to the module that owns it.
 */

import { describe, expect, it } from "vitest";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { readCoreSection } from "../core-section.mjs";

/** A resolved configuration: the fixture's sections, with `core` as given. */
const withCore = (core: unknown): Record<string, unknown> => ({ ...makeValidCoreConfig(), core });

describe("readCoreSection", () => {
	it("answers core's section as its schema parses it, coercing what a variable carries", () => {
		const section = readCoreSection(
			withCore({
				deployment: { mode: "multi" },
				sessionRequirements: { expected: ["mfa"], secondFactorAuthority: "mfa" },
				declaredAbsent: ["auditSink"],
				tokenBinding: {
					dispatchPolicy: "intent-explicit",
					bindConfidentialClientRefreshTokens: "true",
				},
			}),
		);
		expect(section).toEqual({
			deployment: { mode: "multi" },
			sessionRequirements: { expected: ["mfa"], secondFactorAuthority: "mfa" },
			declaredAbsent: ["auditSink"],
			tokenBinding: {
				dispatchPolicy: "intent-explicit",
				bindConfidentialClientRefreshTokens: true,
			},
		});
	});

	it("answers an empty section when the configuration has none", () => {
		expect(readCoreSection({})).toEqual({});
		expect(readCoreSection({ core: undefined })).toEqual({});
	});

	it("reads core's section alone: another section, however written, is neither parsed nor refused", () => {
		const section = readCoreSection({
			oauth: { jwt: { issuer: 42 } },
			widget: { size: "3" },
			core: { deployment: { mode: "single" } },
		});
		expect(section).toEqual({ deployment: { mode: "single" } });
	});

	it("refuses a key the section does not declare, at any level, naming its path and never its value", () => {
		for (const [core, path] of [
			[{ secret: "s3cr3t-value" }, "core"],
			[{ deployment: { mode: "single", replicas: "s3cr3t-value" } }, "core.deployment"],
			[
				{ sessionRequirements: { expected: [], extra: "s3cr3t-value" } },
				"core.sessionRequirements",
			],
		] as const) {
			let thrown: unknown;
			try {
				readCoreSection(withCore(core));
			} catch (err) {
				thrown = err;
			}
			expect(thrown, path).toBeInstanceOf(RangeError);
			const message = (thrown as Error).message;
			expect(message, path).toMatch(/^Config validation failed — 1 issue\(s\) found: /);
			expect(message, path).toContain(`${path}: `);
			expect(message, path).not.toContain("s3cr3t-value");
			// The schema's error is carried as the cause.
			expect((thrown as Error).cause, path).toBeDefined();
		}
	});

	it("refuses a value its schema refuses, naming the path", () => {
		expect(() => readCoreSection(withCore({ deployment: { mode: "triple" } }))).toThrow(
			/^Config validation failed — 1 issue\(s\) found: core\.deployment\.mode: /,
		);
		expect(() => readCoreSection(withCore("core = on"))).toThrow(/found: core: /);
	});

	it("refuses a configuration that is not an object, naming the configuration itself", () => {
		expect(() => readCoreSection("core.deployment.mode = single")).toThrow(
			/^Config validation failed — 1 issue\(s\) found: \(the configuration\): /,
		);
	});

	it("refuses a section whose read throws, carrying what it threw as the cause", () => {
		const core = {
			get deployment(): never {
				throw new Error("the deployment getter broke");
			},
		};
		let thrown: unknown;
		try {
			readCoreSection({ core });
		} catch (err) {
			thrown = err;
		}
		expect(thrown).toBeInstanceOf(RangeError);
		expect((thrown as Error).message).toMatch(
			/^Config validation failed — .*threw instead of answering/,
		);
		expect(((thrown as Error).cause as Error).message).toBe("the deployment getter broke");
	});

	it("changes nothing it was given", () => {
		const given = withCore({
			tokenBinding: {
				dispatchPolicy: "intent-explicit",
				bindConfidentialClientRefreshTokens: "false",
			},
		});
		const before = JSON.stringify(given);
		readCoreSection(given);
		expect(JSON.stringify(given)).toBe(before);
	});
});
