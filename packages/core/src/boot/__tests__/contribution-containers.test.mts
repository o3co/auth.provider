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
 * One container shape per contribution kind, booted through `createApp`: a
 * kind whose collector is name-keyed takes a record, a list-shaped kind takes
 * an array, in `contributes` and in `overrides`, for core's kinds and a
 * consumer's alike; any other container is `contribution-malformed` at stage
 * 1, naming the module, the kind, the channel and what it was given, as the
 * manifest was read once.
 */

import { describe, expect, it } from "vitest";
import { defineModule } from "../../modules/manifest/index.mjs";
import type { Module } from "../../modules/manifest/module-spec.mjs";
import { makeValidCoreConfig } from "../../testing/fixtures/valid-config.mjs";
import { createApp, mergeWithBuiltins } from "../create-app.mjs";
import { BootError, type BootstrapMap } from "../types.mjs";
import { BUILTIN_CONTRIBUTION_KINDS } from "../validate-manifests.mjs";

const bootWith = (): BootstrapMap =>
	({
		config: makeValidCoreConfig() as never,
		pathResolver: (s: string) => s,
	}) satisfies Record<string, unknown> as BootstrapMap;

/** What `createApp` refused with, or a failure when it booted. */
async function refusal(promise: Promise<unknown>): Promise<BootError> {
	try {
		await promise;
	} catch (err) {
		expect(err).toBeInstanceOf(BootError);
		return err as BootError;
	}
	return expect.fail("boot should have been refused");
}

const boot = (modules: readonly Module[], contributionKinds?: Record<string, unknown>) =>
	createApp({
		modules,
		bootstrapComponents: bootWith(),
		...(contributionKinds === undefined ? {} : { contributionKinds: contributionKinds as never }),
	});

const declaring = (
	channel: "contributes" | "overrides",
	kind: string,
	container: unknown,
): Module => defineModule({ name: "container-author", [channel]: { [kind]: container } as never });

/** A consumer's own kinds: one name-keyed, one list-shaped. */
const consumerKinds = () => {
	const { tokenExchangeValidators: widgets, grantPolicyHooks: gadgets } =
		mergeWithBuiltins(undefined);
	if (widgets === undefined || gadgets === undefined) return expect.fail("no seeded collectors");
	return { widgets, gadgets };
};

/** The built-in name-keyed kinds a module may contribute. */
const NAME_KEYED = [
	"grants",
	"tokenExchangeValidators",
	"mfaFactors",
	"sessionRequirements",
	"rateLimitBudgets",
	"federationTypes",
	"admissionActions",
	"sessionCloseNotifiers",
] as const;

/** The built-in list-shaped kinds. */
const LIST_SHAPED = [
	"auditHooks",
	"routes",
	"grantPolicyHooks",
	"grantMiddleware",
	"tokenBindingMechanisms",
	"discoveryMetadata",
] as const;

const expectContainerRefusal = (
	err: BootError,
	kind: string,
	channel: "contributes" | "overrides",
	problem: string,
): void => {
	expect(err.reason).toBe("contribution-malformed");
	expect(err.stage).toBe("validateManifests");
	expect(err.details).toEqual({
		reason: "contribution-malformed",
		module: "container-author",
		kind,
		channel,
		problem,
	});
	expect(err.message).toBe(`Module "container-author" ${channel} ${kind}: ${problem}.`);
};

describe("a name-keyed kind takes a record", () => {
	it.each(NAME_KEYED)("refuses an array contributed under %s", async (kind) => {
		const err = await refusal(boot([declaring("contributes", kind, [() => null])]));
		expectContainerRefusal(
			err,
			kind,
			"contributes",
			"the kind takes a record keyed by name, not an array",
		);
	});

	it.each(NAME_KEYED.filter((kind) => kind !== "sessionRequirements"))(
		"refuses an array overriding %s, as a BootError",
		async (kind) => {
			const err = await refusal(boot([declaring("overrides", kind, [() => null])]));
			expectContainerRefusal(
				err,
				kind,
				"overrides",
				"the kind takes a record keyed by name, not an array",
			);
		},
	);

	it("refuses an array contributed or overridden under a consumer's name-keyed kind", async () => {
		for (const channel of ["contributes", "overrides"] as const) {
			const err = await refusal(
				boot([declaring(channel, "widgets", [() => ({})])], consumerKinds()),
			);
			expectContainerRefusal(
				err,
				"widgets",
				channel,
				"the kind takes a record keyed by name, not an array",
			);
		}
	});

	it.each<readonly [string, unknown, string]>([
		["null", null, "null"],
		["a function", () => null, "a function"],
		["a string", "grant", 'the string "grant"'],
		["a Map", new Map([["urn:test:grant", () => null]]), "a Map, not a plain object"],
	])("refuses %s in a record's place, naming it", async (_label, container, given) => {
		const err = await refusal(boot([declaring("contributes", "grants", container)]));
		expectContainerRefusal(
			err,
			"grants",
			"contributes",
			`the kind takes a record keyed by name, not ${given}`,
		);
	});
});

describe("a list-shaped kind takes an array", () => {
	it.each(LIST_SHAPED)("refuses a record contributed under %s", async (kind) => {
		const err = await refusal(boot([declaring("contributes", kind, { first: () => null })]));
		expectContainerRefusal(err, kind, "contributes", "the kind takes a list, not a record");
	});

	it.each(LIST_SHAPED)("refuses a record overriding %s", async (kind) => {
		const err = await refusal(boot([declaring("overrides", kind, { first: () => null })]));
		expectContainerRefusal(err, kind, "overrides", "the kind takes a list, not a record");
	});

	it("refuses a record contributed or overridden under a consumer's list-shaped kind", async () => {
		for (const channel of ["contributes", "overrides"] as const) {
			const err = await refusal(
				boot([declaring(channel, "gadgets", { first: () => ({}) })], consumerKinds()),
			);
			expectContainerRefusal(err, "gadgets", channel, "the kind takes a list, not a record");
		}
	});

	it.each<readonly [string, unknown, string]>([
		["null", null, "null"],
		["a function", () => null, "a function"],
		["a number", 3, "the number 3"],
	])("refuses %s in a list's place, naming it", async (_label, container, given) => {
		const err = await refusal(boot([declaring("contributes", "routes", container)]));
		expectContainerRefusal(err, "routes", "contributes", `the kind takes a list, not ${given}`);
	});
});

describe("the container as the manifest was read once", () => {
	it("judges the container the first read answered, not what a later read answers", async () => {
		let reads = 0;
		const flipping = {
			name: "container-author",
			get contributes() {
				reads += 1;
				return reads === 1 ? { grants: [() => null] } : { grants: { "urn:test:g": () => null } };
			},
		};
		const err = await refusal(boot([flipping as never]));
		expectContainerRefusal(
			err,
			"grants",
			"contributes",
			"the kind takes a record keyed by name, not an array",
		);
	});
});

describe("containers of the right shape boot", () => {
	it("boots every kind's empty container, and an undefined one", async () => {
		const empty = defineModule({
			name: "empties",
			contributes: {
				...Object.fromEntries(NAME_KEYED.map((kind) => [kind, {}])),
				...Object.fromEntries(LIST_SHAPED.map((kind) => [kind, []])),
				tokenExchangeValidators: undefined,
			} as never,
		});
		const handle = await boot([empty]);
		await handle.dispose();
	});

	it("registers a consumer's kinds' entries from containers of their shape", async () => {
		const kinds = consumerKinds();
		const gadget = { id: "g" };
		const author = defineModule({
			name: "consumer-kinds",
			contributes: {
				grants: { "urn:test:off": () => null },
				widgets: { w: () => ({ id: "w" }) },
				gadgets: [() => gadget],
			} as never,
		});
		const handle = await boot([author], kinds);
		expect(kinds.widgets.get("w")).toEqual({ id: "w" });
		expect([...kinds.gadgets.values()]).toEqual([gadget]);
		await handle.dispose();
	});
});

describe("the built-in kinds' shapes", () => {
	it("agree with the collectors createApp seeds", () => {
		const seeded = Object.entries(mergeWithBuiltins(undefined)).map(
			([kind, collector]) =>
				[kind, (collector as { kind: string }).kind === "name-keyed" ? "record" : "list"] as const,
		);
		expect(new Map(seeded)).toEqual(BUILTIN_CONTRIBUTION_KINDS);
	});
});
