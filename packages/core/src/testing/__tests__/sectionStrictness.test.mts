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
 * `sectionStrictnessProblems`: a module refuses an unknown key at every
 * object level of its own section. Each level of a valid sample is given an
 * unknown key, and each level whose schema keeps or drops the key unread is
 * named by its operator path; a level the caller exempts, with a reason, is
 * not — and an exemption that exempts nothing is named in turn.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "#/modules/manifest/index.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { sectionStrictnessProblems } from "#/testing/sectionStrictness.mjs";

const sectioned = (name: string, schema: z.ZodType, at?: string): Module =>
	defineModule({ name, section: at === undefined ? { schema } : { schema, at } }) as Module;

const Strict = z
	.object({
		retries: z.number().optional(),
		backoff: z.object({ initial: z.number().optional() }).strict().optional(),
	})
	.strict()
	.optional();

describe("sectionStrictnessProblems — the levels that keep an unknown key", () => {
	it("finds nothing in a section strict at every level", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Strict)], {
				tree: { fixture: { retries: 1, backoff: { initial: 2 } } },
			}),
		).toEqual([]);
	});

	it("names the section when its top level strips an unknown key", () => {
		const stripping = z.object({ retries: z.number().optional() }).optional();
		expect(sectionStrictnessProblems([sectioned("fixture", stripping)])).toEqual([
			'fixture: module "fixture"\'s section schema does not refuse an unknown key',
		]);
	});

	it("names a nested level that passes an unknown key through, and not the strict level above it", () => {
		const nestedLoose = z
			.object({ backoff: z.looseObject({ initial: z.number().optional() }).optional() })
			.strict();
		expect(
			sectionStrictnessProblems([sectioned("fixture", nestedLoose)], {
				tree: { fixture: { backoff: { initial: 1 } } },
			}),
		).toEqual([
			'fixture.backoff: module "fixture"\'s section schema does not refuse an unknown key',
		]);
	});

	it("checks only the levels the sample holds: a nested object it leaves out is not reached", () => {
		const nestedLoose = z
			.object({ backoff: z.looseObject({ initial: z.number().optional() }).optional() })
			.strict()
			.optional();
		expect(sectionStrictnessProblems([sectioned("fixture", nestedLoose)])).toEqual([]);
	});

	it("names an open record's level, whatever its entries take: an unknown key is an object there", () => {
		const open = z.record(z.string(), z.record(z.string(), z.unknown())).optional();
		expect(sectionStrictnessProblems([sectioned("fixture", open)])).toEqual([
			'fixture: module "fixture"\'s section schema does not refuse an unknown key',
		]);
	});

	it("checks each entry of a record and each element of a list as a level of its own", () => {
		const entries = z
			.object({
				limits: z.record(z.string(), z.looseObject({ limit: z.number().optional() })),
				hosts: z.array(z.looseObject({ name: z.string() })),
			})
			.strict();
		expect(
			sectionStrictnessProblems([sectioned("fixture", entries)], {
				tree: { fixture: { limits: { login: { limit: 5 } }, hosts: [{ name: "a" }] } },
			}),
		).toEqual([
			'fixture.hosts.0: module "fixture"\'s section schema does not refuse an unknown key',
			'fixture.limits.login: module "fixture"\'s section schema does not refuse an unknown key',
			'fixture.limits: module "fixture"\'s section schema does not refuse an unknown key',
		]);
	});

	it("names the section at its transitional path when the module declares `at`", () => {
		const stripping = z.object({ retries: z.number().optional() }).optional();
		expect(
			sectionStrictnessProblems([sectioned("fixture", stripping, "legacy.fixture")], {
				tree: { legacy: { fixture: { retries: 1 } } },
			}),
		).toEqual([
			'legacy.fixture: module "fixture"\'s section schema does not refuse an unknown key',
		]);
	});

	it("skips a module without a section", () => {
		expect(sectionStrictnessProblems([defineModule({ name: "plain" }) as Module])).toEqual([]);
	});
});

describe("sectionStrictnessProblems — the sample each section is checked from", () => {
	const Required = z.object({ url: z.string(), tls: z.looseObject({}) }).strict();

	it("reads the sample at the section's path in `tree`", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Required)], {
				tree: { fixture: { url: "https://a.test", tls: {} } },
			}),
		).toEqual(['fixture.tls: module "fixture"\'s section schema does not refuse an unknown key']);
	});

	it("takes a sample named for the module over the tree", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Required)], {
				tree: { fixture: { nothing: true } },
				samples: { fixture: { url: "https://a.test", tls: {} } },
			}),
		).toEqual(['fixture.tls: module "fixture"\'s section schema does not refuse an unknown key']);
	});

	it("names a section whose sample its schema refuses, rather than counting every level refused", () => {
		const problems = sectionStrictnessProblems([sectioned("fixture", Required)]);
		expect(problems).toHaveLength(1);
		expect(problems[0]).toMatch(
			/^fixture: module "fixture"'s sample is refused by its section schema — /,
		);
	});

	it("names a section whose schema cannot answer synchronously", () => {
		const async = z
			.object({})
			.strict()
			.refine(async () => true);
		const problems = sectionStrictnessProblems([sectioned("fixture", async)]);
		expect(problems).toHaveLength(1);
		expect(problems[0]).toMatch(
			/^fixture: module "fixture"'s sample is refused by its section schema — /,
		);
	});
});

describe("sectionStrictnessProblems — levels exempt by the caller", () => {
	const Sinks = z.record(z.string(), z.record(z.string(), z.unknown())).optional();

	it("does not name a level the caller exempts with a reason", () => {
		expect(
			sectionStrictnessProblems([sectioned("sinks", Sinks)], {
				exempt: { sinks: "each key names a sink the deployment registers" },
			}),
		).toEqual([]);
	});

	it("matches one segment of an exempt path with `*`", () => {
		expect(
			sectionStrictnessProblems([sectioned("sinks", Sinks)], {
				tree: { sinks: { splunk: { token: "t" }, file: {} } },
				exempt: {
					sinks: "each key names a sink the deployment registers",
					"sinks.*": "each sink's builder holds its own options",
				},
			}),
		).toEqual([]);
	});

	it("names an exemption without a reason", () => {
		expect(
			sectionStrictnessProblems([sectioned("sinks", Sinks)], { exempt: { sinks: " " } }),
		).toEqual(["sinks: exempt with no reason"]);
	});

	it("names an exemption in a checked section that exempts nothing, so the list only shrinks", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Strict)], {
				tree: { fixture: { backoff: {} } },
				exempt: {
					"fixture.backoff": "was open",
					"fixture.missing": "never there",
				},
			}),
		).toEqual([
			'fixture.backoff: exempt, but no level of module "fixture"\'s section it matches keeps an unknown key',
			'fixture.missing: exempt, but no level of module "fixture"\'s section it matches keeps an unknown key',
		]);
	});

	it("leaves an exemption outside every checked section to the check that holds its module", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Strict)], {
				exempt: { sinks: "each key names a sink the deployment registers" },
			}),
		).toEqual([]);
	});
});
