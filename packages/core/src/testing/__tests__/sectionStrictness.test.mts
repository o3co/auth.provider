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
 * not — and an exemption that exempts nothing is named in turn. Every object
 * level the schema declares, and every form of a union, must be reached by a
 * sample, or the level is named as not reached.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";
import { defineModule } from "#/modules/manifest/index.mjs";
import type { Module } from "#/modules/manifest/module-spec.mjs";
import { sectionStrictnessProblems } from "#/testing/sectionStrictness.mjs";

const sectioned = (name: string, schema: z.ZodType): Module =>
	defineModule({ name, section: { schema } }) as Module;

const keeps = (path: string, module = "fixture") =>
	`${path}: module "${module}"'s section schema does not refuse an unknown key`;
const unreached = (path: string, module = "fixture") =>
	`${path}: not reached by module "${module}"'s samples`;

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
			keeps("fixture"),
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
		).toEqual([keeps("fixture.backoff")]);
	});

	it("names an open record's level and its entries' levels", () => {
		const open = z.record(z.string(), z.record(z.string(), z.unknown())).optional();
		expect(
			sectionStrictnessProblems([sectioned("fixture", open)], {
				tree: { fixture: { splunk: { token: "t" } } },
			}),
		).toEqual([keeps("fixture.splunk"), keeps("fixture")]);
	});

	it("names a record whose entries refuse a string and an empty object: an unknown key copying an entry is kept", () => {
		const limits = z
			.object({
				limits: z.record(z.string(), z.object({ limit: z.number() }).strict()),
			})
			.strict();
		expect(
			sectionStrictnessProblems([sectioned("fixture", limits)], {
				tree: { fixture: { limits: { login: { limit: 5 } } } },
			}),
		).toEqual([keeps("fixture.limits")]);
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
		).toEqual([keeps("fixture.hosts.0"), keeps("fixture.limits.login"), keeps("fixture.limits")]);
	});

	it("reads the section at the module's name, never split on its dots", () => {
		const stripping = z.object({ retries: z.number().optional() }).optional();
		expect(
			sectionStrictnessProblems([sectioned("legacy.fixture", stripping)], {
				tree: { "legacy.fixture": { retries: 1 }, legacy: { fixture: { retries: "x" } } },
			}),
		).toEqual([keeps("legacy.fixture", "legacy.fixture")]);
	});

	it("skips a module without a section", () => {
		expect(sectionStrictnessProblems([defineModule({ name: "plain" }) as Module])).toEqual([]);
	});
});

describe("sectionStrictnessProblems — every level the schema declares is reached", () => {
	it("names a nested block no sample holds", () => {
		expect(sectionStrictnessProblems([sectioned("fixture", Strict)])).toEqual([
			unreached("fixture.backoff"),
		]);
	});

	it("names a record's entries and a list's elements when no sample holds one", () => {
		const entries = z
			.object({
				limits: z.record(z.string(), z.object({ limit: z.number() }).strict()),
				hosts: z.array(z.object({ name: z.string() }).strict()),
			})
			.strict();
		expect(
			sectionStrictnessProblems([sectioned("fixture", entries)], {
				tree: { fixture: { limits: {}, hosts: [] } },
			}),
		).toEqual([unreached("fixture.hosts.*"), unreached("fixture.limits.*")]);
	});

	it("names each form of a union no sample takes, by its keys", () => {
		const forms = z
			.object({
				store: z.union([
					z.object({ type: z.literal("file"), path: z.string() }).strict(),
					z
						.object({
							type: z.literal("remote"),
							tls: z.object({ ca: z.string() }).strict(),
						})
						.strict(),
				]),
			})
			.strict();
		expect(
			sectionStrictnessProblems([sectioned("fixture", forms)], {
				tree: { fixture: { store: { type: "file", path: "/k" } } },
			}),
		).toEqual([
			unreached("fixture.store.tls"),
			'fixture.store: its form with keys tls, type is not reached by module "fixture"\'s samples',
		]);
		expect(
			sectionStrictnessProblems([sectioned("fixture", forms)], {
				tree: { fixture: { store: { type: "file", path: "/k" } } },
				samples: { fixture: [{ store: { type: "remote", tls: { ca: "pem" } } }] },
			}),
		).toEqual([]);
	});
});

describe("sectionStrictnessProblems — the samples each section is checked from", () => {
	const Required = z.object({ url: z.string(), tls: z.looseObject({}) }).strict();

	it("reads a sample at the section's path in `tree`", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Required)], {
				tree: { fixture: { url: "https://a.test", tls: {} } },
			}),
		).toEqual([keeps("fixture.tls")]);
	});

	it("checks each sample given for the module beside the tree's", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture", Required)], {
				samples: { fixture: [{ url: "https://a.test", tls: {} }] },
			}),
		).toEqual([keeps("fixture.tls")]);
		const problems = sectionStrictnessProblems([sectioned("fixture", Required)], {
			tree: { fixture: { nothing: true } },
			samples: { fixture: [{ url: "https://a.test", tls: {} }] },
		});
		expect(problems).toHaveLength(2);
		expect(problems).toContain(keeps("fixture.tls"));
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
	const Counts = z.record(z.string(), z.number()).optional();
	const Sinks = z.record(z.string(), z.record(z.string(), z.unknown())).optional();

	it("does not name a level the caller exempts with a reason", () => {
		expect(
			sectionStrictnessProblems([sectioned("counts", Counts)], {
				tree: { counts: { login: 5 } },
				exempt: { counts: "each key names a prefix the deployment chooses" },
			}),
		).toEqual([]);
	});

	it("reads an exemption of a dotted module's name as its section's root, one key", () => {
		expect(
			sectionStrictnessProblems([sectioned("fixture.section", Counts)], {
				tree: { "fixture.section": { login: 5 } },
				exempt: { "fixture.section": "each key names a prefix the deployment chooses" },
			}),
		).toEqual([]);
		expect(
			sectionStrictnessProblems([sectioned("fixture.section", Sinks)], {
				tree: { "fixture.section": { splunk: { token: "t" } } },
				exempt: {
					"fixture.section": "each key names a sink the deployment registers",
					"fixture.section.*": "each sink's builder holds its own options",
				},
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
			sectionStrictnessProblems([sectioned("counts", Counts)], {
				tree: { counts: { login: 5 } },
				exempt: { counts: " " },
			}),
		).toEqual(["counts: exempt with no reason"]);
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
				tree: { fixture: { backoff: {} } },
				exempt: { sinks: "each key names a sink the deployment registers" },
			}),
		).toEqual([]);
	});
});
