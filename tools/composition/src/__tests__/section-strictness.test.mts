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
 * Every module of the full set refuses an unknown key at every object level of
 * its own section (core's `sectionStrictnessProblems`), so a typo or a key an
 * older version read refuses boot naming its path instead of being dropped
 * unread. Each section is sampled from the configuration the full set boots
 * with, every loaded package's `reference.conf` beneath it. A level whose keys
 * are open by design is exempt, with its reason; a module not yet strict is on
 * an allowlist that may only shrink: an entry whose module now refuses every
 * unknown key fails, and so does a module off the list that keeps one.
 */

import type { Module } from "@o3co/auth-provider-core";
import { sectionStrictnessProblems } from "@o3co/auth-provider-core/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { composeFullSet, type FullSet } from "./full-set.fixture.mjs";

/** The levels whose keys are open by design, each with why. */
const EXEMPT: Readonly<Record<string, string>> = {
	"audit-sink":
		"each key names a sink the deployment registers in the template's audit-sink module, and each sink's builder holds its own options to its rules",
};

/**
 * The modules whose sections still keep an unknown key somewhere, each with
 * where. The list only shrinks: a module leaves it in the change that makes
 * its section strict.
 */
const NOT_YET_STRICT: Readonly<Record<string, string>> = {
	oauth: "the section and each nested block",
	mfa: "the section and each nested block",
	"mfa-totp-factor": "the section",
	webauthn: "the section and its rateLimit blocks",
	"session-store": "storage, passed through to the store",
};

describe("every module of the full set refuses an unknown key in its own section", () => {
	let set: FullSet;
	let sectioned: readonly Module[];

	beforeAll(async () => {
		set = await composeFullSet();
		sectioned = set.modules.filter((module) => module.section !== undefined);
	});

	afterAll(async () => {
		await set?.handle.dispose();
	});

	const problemsOf = (modules: readonly Module[]): string[] =>
		sectionStrictnessProblems(modules, { tree: set.resolved, exempt: EXEMPT });

	it("checks the sections of every package's modules (the guard is not vacuous)", () => {
		expect(sectioned.map((module) => module.name)).toEqual(
			expect.arrayContaining([
				"jwks",
				"session",
				"oauth-authorization",
				"device-grant",
				"dpop",
				"mtls",
				"oauth-token-exchange",
				"webauthn",
				"mfa",
				"audit-sink",
				"core-rate-limiter-memory",
			]),
		);
	});

	it("finds no level keeping an unknown key outside the allowlist", () => {
		expect(
			problemsOf(sectioned.filter((module) => !Object.hasOwn(NOT_YET_STRICT, module.name))),
		).toEqual([]);
	});

	it.each(Object.keys(NOT_YET_STRICT))(
		"still finds a level keeping an unknown key in %s, or the entry goes",
		(name) => {
			const module = sectioned.find((candidate) => candidate.name === name);
			expect(module, `${name} is not a sectioned module of the full set`).toBeDefined();
			expect(problemsOf([module as Module])).toContainEqual(
				expect.stringMatching(/: module ".+"'s section schema does not refuse an unknown key$/),
			);
		},
	);
});
