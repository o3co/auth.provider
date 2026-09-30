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
 * The `admissionActions` contribution kind, booted through `createApp`: each
 * consumer registers the actions it admits, keyed by name, with one of core's
 * grades; boot reads each declaration once, at stage 1, and refuses a
 * malformed name, a grade outside the grades, a second claimant and an
 * override; admission admits a registered action by its name and refuses one
 * nothing registers at the consumer's call.
 */

import { describe, expect, it } from "vitest";
import { BootError } from "#/boot/types.mjs";
import { createApp, defineModule, type Module } from "#/index.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import { admitSession, cookieClaim } from "#/session-admission/admit.mjs";
import type { AdmissionAction } from "#/session-admission/actions.mjs";
import type {
	SessionRequirement,
	SessionRequirementResolver,
} from "#/session-admission/requirement.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const boot = (
	modules: readonly Module[],
	expected: readonly string[] = [],
	extra: Partial<Parameters<typeof createApp>[0]> = {},
) =>
	createApp({
		modules,
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), sessionRequirements: { expected } },
			pathResolver: (p: string) => p,
		} as never,
		...extra,
	});

const refusal = async (promise: Promise<unknown>): Promise<BootError> => {
	const err = await promise.then(
		() => undefined,
		(caught: unknown) => caught,
	);
	expect(err).toBeInstanceOf(BootError);
	return err as BootError;
};

/** A module registering `actions` and nothing else. */
const registering = (name: string, actions: unknown, channel: "contributes" | "overrides" = "contributes") =>
	defineModule({ name, [channel]: { admissionActions: actions } } as never);

/** A consumer of admission: it requires the resolver and keeps what it was handed. */
const consumer = (seen: { resolver?: SessionRequirementResolver }, actions?: unknown) =>
	defineModule({
		name: "test:consumer",
		requires: ["sessionRequirementResolver"] as const,
		contributes: {
			...(actions === undefined ? {} : { admissionActions: actions }),
			routes: [
				(deps: { sessionRequirementResolver?: SessionRequirementResolver }) => {
					seen.resolver = deps.sessionRequirementResolver;
					return {
						id: "test-consumer",
						mountPath: "/__test_consumer__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					};
				},
			],
		},
	} as never);

/** A requirement that records the action it is asked about. */
const probe = (seen: AdmissionAction[]) =>
	defineModule({
		name: "test:probe",
		contributes: {
			sessionRequirements: {
				probe: (): SessionRequirement => ({
					name: "probe",
					reach: new Set(),
					stepUpPage: undefined,
					remediations: [],
					hintKeys: [],
					admit: async ({ action }) => {
						seen.push(action);
						return { outcome: "met" };
					},
				}),
			},
		},
	} as never);

const admit = (resolver: SessionRequirementResolver, action: string) =>
	admitSession(
		{
			userSessionStore: undefined,
			subjectRevocation: undefined,
			requirements: resolver,
			acrTable: readAcrTable({}),
			logger: undefined,
			auditSink: undefined,
		},
		{
			claim: cookieClaim({
				session: { isAuthenticated: true, sid: "sid-1", user: { id: "user-1" } },
			}),
			action,
		},
	);

describe("the admissionActions kind — registered through createApp", () => {
	it("registers each action under its name, and admission admits it by that name with the grade it registered", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const asked: AdmissionAction[] = [];
		const handle = await boot(
			[
				consumer(seen, {
					"acme.export": { grade: "credential_change" },
					"acme.peek": { grade: "grants_nothing" },
				}),
				probe(asked),
			],
			["probe"],
		);
		try {
			const resolver = seen.resolver as SessionRequirementResolver;
			expect(resolver.action("acme.export")).toEqual({
				name: "acme.export",
				grade: "credential_change",
			});
			expect(await admit(resolver, "acme.export")).toMatchObject({ outcome: "admitted" });
			expect(await admit(resolver, "acme.peek")).toMatchObject({ outcome: "admitted" });
			expect(asked).toEqual([
				{ name: "acme.export", grade: "credential_change" },
				{ name: "acme.peek", grade: "grants_nothing" },
			]);
		} finally {
			await handle.dispose();
		}
	});

	it("reads each declaration once, at stage 1: changing it after boot changes nothing registered", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const declaration: { grade: string } = { grade: "credential_change" };
		const handle = await boot([consumer(seen, { "acme.export": declaration })]);
		try {
			declaration.grade = "grants_nothing";
			expect(seen.resolver?.action("acme.export")?.grade).toBe("credential_change");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses, at the consumer's call, an action no module registers", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot([
			consumer(seen, { "acme.export": { grade: "use" } }),
			registering("test:other", { "other.peek": { grade: "grants_nothing" } }),
		]);
		try {
			const resolver = seen.resolver as SessionRequirementResolver;
			expect(await admit(resolver, "other.peek")).toMatchObject({ outcome: "admitted" });
			await expect(admit(resolver, "acme.import")).rejects.toThrow(
				/"acme\.import" is not a registered admission action/,
			);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the admissionActions kind — refused", () => {
	it("two modules claiming one action refuse boot at stage 1, naming both", async () => {
		const err = await refusal(
			boot([
				registering("test:first", { "acme.export": { grade: "use" } }),
				registering("test:second", { "acme.export": { grade: "use" } }),
			]),
		);
		expect(err.reason).toBe("duplicate-contribute");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			kind: "admissionActions",
			identity: "acme.export",
			modules: ["test:first", "test:second"],
		});
	});

	it.each([
		["a name outside the grammar", { "Acme.Export": { grade: "use" } }, "Acme.Export", /two lower-case identifiers/],
		["a name of one identifier", { export: { grade: "use" } }, "export", /two lower-case identifiers/],
		["a grade outside the grades", { "acme.export": { grade: "read" } }, "acme.export", /grade must be one of/],
		["no grade", { "acme.export": {} }, "acme.export", /grade must be one of/],
		["the remediation grade", { "acme.export": { grade: "remediation" } }, "acme.export", /remediation is not an action's grade/],
		["a declaration that is not an object", { "acme.export": "use" }, "acme.export", /a declaration is an object/],
		["a null declaration", { "acme.export": null }, "acme.export", /a declaration is an object/],
	])("%s is refused at stage 1, naming the module and the action", async (_what, actions, name, problem) => {
		const err = await refusal(boot([registering("test:acme", actions)]));
		expect(err.reason).toBe("contribution-malformed");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toMatchObject({
			module: "test:acme",
			kind: "admissionActions",
			name,
			channel: "contributes",
		});
		expect((err.details as { problem: string }).problem).toMatch(problem);
	});

	it.each([
		["an array", [{ grade: "use" }]],
		["null", null],
		["a function", () => ({ grade: "use" })],
	])("a container that is %s is refused at stage 1", async (_what, actions) => {
		const err = await refusal(boot([registering("test:acme", actions)]));
		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({ module: "test:acme", kind: "admissionActions" });
		expect(err.details).not.toHaveProperty("name");
	});

	it("an override of an action is refused at stage 1: an action's grade is its registrant's", async () => {
		const err = await refusal(
			boot([
				registering("test:acme", { "acme.export": { grade: "credential_change" } }),
				registering("test:loosen", { "acme.export": { grade: "use" } }, "overrides"),
			]),
		);
		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({
			module: "test:loosen",
			kind: "admissionActions",
			name: "acme.export",
			channel: "overrides",
		});
	});

	it("a host collector for the kind is refused: the collector is the planner's", async () => {
		const err = await refusal(
			boot([], [], {
				contributionKinds: {
					admissionActions: {
						kind: "name-keyed",
						register: () => {},
						replace: () => {},
						get: () => undefined,
						entries: () => [][Symbol.iterator](),
					},
				} as never,
			}),
		);
		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toMatchObject({ kind: "admissionActions" });
	});

	it("a requirement whose remediation is a registered action's name refuses boot: registered as a remediation it would skip every requirement for that action", async () => {
		const err = await refusal(
			boot(
				[
					registering("test:acme", { "acme.export": { grade: "use" } }),
					defineModule({
						name: "test:requirement",
						contributes: {
							sessionRequirements: {
								acme: (): SessionRequirement => ({
									name: "acme",
									reach: new Set(),
									stepUpPage: undefined,
									remediations: ["acme.export"],
									hintKeys: [],
									admit: async () => ({ outcome: "met" }),
								}),
							},
						},
					} as never),
				],
				["acme"],
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:requirement",
			kind: "sessionRequirements",
			name: "acme",
		});
		expect(err.message).toMatch(/acme\.export/);
	});
});
