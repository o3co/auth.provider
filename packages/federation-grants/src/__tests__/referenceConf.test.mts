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
 * The package's `config/reference.conf`: the federation-grants module reads
 * its own section, `federation-grants`, declares this file as its section's
 * reference, and the file holds only that section, which the section's schema
 * parses without losing a path — core's `packageReferenceProblems`. Each
 * variable is named after the path it sets.
 */

import { fileURLToPath } from "node:url";
import { packageReferenceProblems } from "@o3co/auth-provider-core/testing";
import { parseFile } from "@o3co/ts.hocon";
import { describe, expect, it } from "vitest";
import { federationGrantsModule } from "#/module.mjs";

/** The package's defaults, as a composition root finds them. */
const REFERENCE = new URL("../../config/reference.conf", import.meta.url);

const read = (path: string, env: Readonly<Record<string, string>>): unknown =>
	parseFile(path, { env: { ...env } }).toObject();

/** The `federation-grants` section the file resolves to with `env` set. */
const section = (env: Readonly<Record<string, string>> = {}): Record<string, unknown> =>
	(read(fileURLToPath(REFERENCE), env) as { "federation-grants": Record<string, unknown> })[
		"federation-grants"
	];

describe("the package's config/reference.conf", () => {
	it("is read at the section named after its module", () => {
		expect([
			federationGrantsModule.name,
			federationGrantsModule.section !== undefined,
			federationGrantsModule.section?.at,
			federationGrantsModule.configSchema,
		]).toEqual(["federation-grants", true, undefined, undefined]);
	});

	it("is declared by the module and holds only its section, which its schema parses without losing a path", () => {
		expect(
			packageReferenceProblems({ reference: REFERENCE, modules: [federationGrantsModule], read }),
		).toEqual([]);
	});

	it("ships the feature off, with the lifetimes and timings, and no store's key", () => {
		expect(section()).toEqual({
			enabled: false,
			defaultExpiresIn: 2592000,
			maxExpiresIn: 2592000,
			refreshBuffer: 30,
			ineligibleRetryAfter: 300,
			refreshFailureBackoff: 30,
			upstreamTimeoutMs: 10000,
			upstreamHardTimeoutMs: 25000,
			refreshLockTtlMs: 30000,
			lockWaitMs: 5000,
			persistRetryBudgetMs: 3000,
			allowKeepOnSubjectRevocation: false,
			identityLookup: "required",
			consent: {},
			connections: {},
		});
	});

	it.each([
		["FEDERATION_GRANTS_ENABLED", "enabled"],
		["FEDERATION_GRANTS_ALLOW_KEEP_ON_SUBJECT_REVOCATION", "allowKeepOnSubjectRevocation"],
		["FEDERATION_GRANTS_IDENTITY_LOOKUP", "identityLookup"],
	])("binds %s at federation-grants.%s", (variable, key) => {
		expect(section({ [variable]: "__set__" })[key]).toBe("__set__");
	});

	it("binds FEDERATION_GRANTS_CONSENT_URL at federation-grants.consent.url", () => {
		expect(section({ FEDERATION_GRANTS_CONSENT_URL: "/consent/grants" }).consent).toEqual({
			url: "/consent/grants",
		});
	});
});
