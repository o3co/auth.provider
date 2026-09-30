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
 * The `sessionRequirements` contribution kind and its read side,
 * `sessionRequirementResolver`, booted through `createApp` (see ADR
 * 2026-09-28-session-admission): registration in init order and the branded
 * projection, the three refusals that keep a requirement from being switched
 * off from behind the consumers, the checks at the end of stage 4, and the
 * boot line.
 */

import { describe, expect, it } from "vitest";
import { BootError } from "#/boot/types.mjs";
import {
	createApp,
	defineModule,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
} from "#/index.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import type { MfaFactor } from "#/mfa/factor.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitPrimary,
	admitSession,
	cookieClaim,
	passwordPrimary,
	resumePrimary,
} from "#/session-admission/admit.mjs";
import {
	issuedRemediationActions,
	type PrimaryContinuation,
	type SessionRequirement,
	type SessionRequirementResolver,
} from "#/session-admission/requirement.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { createTestOAuthTokenSettings } from "#/testing/slots/oauthTokenSettings.mjs";

const config = (over: Record<string, unknown> = {}) => ({
	...makeValidCoreConfig(),
	core: { sessionRequirements: { expected: [] } },
	...over,
});

interface Line {
	readonly level: string;
	readonly fields: Record<string, unknown>;
	readonly message: string | undefined;
}

const recordingLogger = (): { readonly logger: Logger; readonly lines: Line[] } => {
	const lines: Line[] = [];
	const at =
		(level: string) =>
		(first: unknown, second?: unknown): void => {
			lines.push({
				level,
				fields:
					typeof first === "object" && first !== null ? (first as Record<string, unknown>) : {},
				message: typeof first === "string" ? first : (second as string | undefined),
			});
		};
	const logger = {
		trace: () => {},
		debug: () => {},
		info: at("info"),
		warn: at("warn"),
		error: at("error"),
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, lines };
};

const requirement = (name: string, over: Partial<SessionRequirement> = {}): SessionRequirement => ({
	name,
	reach: new Set(),
	stepUpPage: undefined,
	remediations: [`${name}.step_up`],
	hintKeys: [],
	admit: async () => ({ outcome: "met" }),
	...over,
});

/** A module contributing `requirements` under the keys given. */
const contributing = (
	moduleName: string,
	requirements: Record<string, () => SessionRequirement | null>,
) =>
	defineModule({
		name: moduleName,
		contributes: { sessionRequirements: requirements as never },
	});

/** A consumer of admission: it requires the resolver and holds what it was handed. */
const consumer = (
	seen: { resolver?: SessionRequirementResolver },
	key: "requires" | "optional" = "requires",
) =>
	defineModule({
		name: "test:consumer",
		[key]: ["sessionRequirementResolver"] as const,
		contributes: {
			admissionActions: { "test.use": { grade: "use" } },
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

const boot = (
	modules: Parameters<typeof createApp>[0]["modules"],
	over: Record<string, unknown> = {},
	extra: Partial<Parameters<typeof createApp>[0]> = {},
	logger?: Logger,
	/** Components the host bootstraps beside the configuration. */
	components: Record<string, unknown> = {},
) =>
	createApp({
		modules,
		bootstrapComponents: {
			config: config(over),
			pathResolver: (p: string) => p,
			...(logger === undefined ? {} : { logger }),
			...components,
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

const factor = (kind: string, amrValues: readonly string[], addsMfa: boolean): MfaFactor => ({
	kind,
	amrValues,
	addsMfa,
	counting: true,
	guessable: false,
	amrFor: () => [...amrValues],
	describe: () => ({}),
	verify: async () => ({ ok: false, reason: "invalid" }),
	beginEnrollment: async () => ({ state: {}, response: {} }),
	completeEnrollment: async () => ({ ok: false, reason: "invalid" }),
});

/** A name-keyed collector a host might try to hand in for a built-in kind. */
const stores = [memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule];

/**
 * An MFA implementation, under a name that is not `mfa`: declares the
 * second-factor authority, requires the three ports, reaches what the factors
 * reach, declares its `step_up` remediation.
 */
const authorityModule = (
	over: Partial<SessionRequirement> = {},
	requires?: readonly string[],
	name = "verifier",
	moduleName = "test:verifier",
) =>
	defineModule({
		name: moduleName,
		requires: (requires ?? ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"]) as never,
		contributes: {
			sessionRequirements: {
				[name]: (deps: {
					mfaFactorResolver?: { entries(): Iterable<readonly [string, MfaFactor]> };
				}) => ({
					name,
					secondFactorAuthority: true,
					// A real getter over the resolver, read after the pass: a
					// spread would read it at factory time, before the factors.
					get reach() {
						const reach = new Set<string>();
						for (const [, f] of deps.mfaFactorResolver?.entries() ?? []) {
							for (const value of f.amrValues) reach.add(value);
							if (f.addsMfa) reach.add("mfa");
						}
						return reach;
					},
					stepUpPage: { url: `/${name}`, params: {} },
					remediations: [`${name}.step_up`],
					hintKeys: [],
					admit: async () => ({ outcome: "met" as const }),
					...over,
				}),
			},
		},
	} as never);

const hostCollector = () => ({
	kind: "name-keyed" as const,
	register: () => {},
	replace: () => {},
	get: () => undefined,
	entries: () => [][Symbol.iterator](),
});

describe("the sessionRequirements kind and sessionRequirementResolver", () => {
	it("registers each requirement under its key in init order, projects them through the resolver, and admitSession accepts that resolver", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:second", { b: () => requirement("b") }),
				contributing("test:first", { a: () => requirement("a") }),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["a", "b"] } } },
		);
		try {
			const resolver = seen.resolver as SessionRequirementResolver;
			expect(resolver).toBeDefined();
			expect([...resolver.entries()].map(([name, r]) => [name, r.name])).toEqual([
				["b", "b"],
				["a", "a"],
			]);
			expect(resolver.get("a")?.remediations).toEqual(["a.step_up"]);
			expect(resolver.get("missing")).toBeUndefined();
			expect(handle.components.sessionRequirementResolver).toBe(resolver);
			const admission = await admitSession(
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
					action: "test.use",
				},
			);
			expect(admission).toEqual({ outcome: "admitted", session: null, acr: undefined });
		} finally {
			await handle.dispose();
		}
	});

	it("hands a provider the projection before stage 3, and refuses a read while the provides factories run", async () => {
		const provider = defineModule({
			name: "test:reads-early",
			requires: ["sessionRequirementResolver"] as const,
			provides: {
				auditSink: ({ sessionRequirementResolver }) => {
					sessionRequirementResolver.get("a");
					return { kind: "stub", record: async () => {} } as never;
				},
			},
		});
		const reader = defineModule({
			name: "test:reads-audit-sink",
			requires: ["auditSink"] as const,
			contributes: {
				routes: [
					() => ({
						id: "test-reads-audit-sink",
						mountPath: "/__test_reads_audit_sink__",
						handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
					}),
				],
			},
		});
		const err = await refusal(boot([provider, reader]));
		expect(err.reason).toBe("provides-factory-failed");
		expect(err.message).toMatch(/read it at request time/);
	});

	it("refuses a factory that answers null, and a name that is not the key: contribute-factory-failed", async () => {
		const seen = {};
		const nulled = await refusal(
			boot([contributing("test:nulled", { a: () => null }), consumer(seen)], {
				core: { sessionRequirements: { expected: ["a"] } },
			}),
		);
		expect(nulled.reason).toBe("contribute-factory-failed");
		expect(nulled.details).toMatchObject({
			module: "test:nulled",
			kind: "sessionRequirements",
			name: "a",
		});
		const misnamed = await refusal(
			boot([contributing("test:misnamed", { a: () => requirement("other") }), consumer(seen)], {
				core: { sessionRequirements: { expected: ["a"] } },
			}),
		);
		expect(misnamed.reason).toBe("contribute-factory-failed");
		expect(misnamed.message).toMatch(/name/);
	});

	it("refuses a requirement named for a store admission names its own outage by — user_session, revocation_boundary — as the contribution's failure: a consumer telling an outage by its store would take the requirement's for the store's", async () => {
		for (const name of ["user_session", "revocation_boundary"]) {
			const err = await refusal(
				boot([contributing("test:named", { [name]: () => requirement(name) })], {
					core: { sessionRequirements: { expected: [name] } },
				}),
			);
			expect(err.reason, name).toBe("contribute-factory-failed");
			expect(err.details, name).toMatchObject({
				module: "test:named",
				kind: "sessionRequirements",
				name,
			});
			expect(err.message, name).toMatch(/outage/);
		}
	});

	it("refuses a requirement whose name is not RFC 6749's error-code characters — a quote, a backslash, a control character, non-ASCII — as the contribution's failure: a step_up names it on the wire, where such a name is dropped", async () => {
		for (const name of ['a "quoted" name', "back\\slash", "tab\there", "caf\u00e9"]) {
			const err = await refusal(
				boot([contributing("test:named", { [name]: () => requirement(name) })], {
					core: { sessionRequirements: { expected: [name] } },
				}),
			);
			expect(err.reason, name).toBe("contribute-factory-failed");
			expect(err.details, name).toMatchObject({
				module: "test:named",
				kind: "sessionRequirements",
				name,
			});
			expect(err.message, name).toMatch(/error-code characters/);
		}
	});
});

describe("the kind guard: no override of sessionRequirements, and no host collector for a guarded kind", () => {
	it("refuses an override of sessionRequirements: session-requirement-kind-guarded", async () => {
		const overriding = defineModule({
			name: "test:overriding",
			overrides: { sessionRequirements: { a: () => requirement("a") } },
		} as never);
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), overriding], {
				core: { sessionRequirements: { expected: ["a"] } },
			}),
		);
		expect(err.reason).toBe("session-requirement-kind-guarded");
		expect(err.stage).toBe("validateManifests");
		expect(err.details).toEqual({
			reason: "session-requirement-kind-guarded",
			kind: "sessionRequirements",
			channel: "overrides",
			module: "test:overriding",
		});
	});

	it.each(["sessionRequirements", "mfaFactors"] as const)(
		"refuses a host contributionKinds entry for %s in createApp, before the kinds are merged and the manifests validated: session-requirement-kind-guarded",
		async (kind) => {
			const err = await refusal(
				boot([], {}, { contributionKinds: { [kind]: hostCollector() } as never }),
			);
			expect(err.reason).toBe("session-requirement-kind-guarded");
			expect(err.details).toEqual({
				reason: "session-requirement-kind-guarded",
				kind,
				channel: "contributionKinds",
			});
			// Before stage 1: a module list that would not validate is not reached.
			const first = await refusal(
				createApp({
					modules: [{ name: "" } as never],
					bootstrapComponents: { config: config(), pathResolver: (p: string) => p } as never,
					contributionKinds: { [kind]: hostCollector() } as never,
				}),
			);
			expect(first.reason).toBe("session-requirement-kind-guarded");
		},
	);

	it("keeps accepting a host collector for any other kind", async () => {
		const handle = await boot([], {}, { contributionKinds: { grants: hostCollector() } as never });
		await handle.dispose();
	});
});

describe("a requirement that reaches nothing completes an interruption with an empty addition", () => {
	it("interrupts a login through boot's own resolver, is resumed with amr [] — read back through the persisted DTO — and establishes over pwd alone", async () => {
		// Two requirements a deployment might write, neither reaching anything
		// (only mfa does): each interrupts until its own record says the
		// ceremony completed, which is the requirement's state, not the
		// primary's — a completion adds nothing to `recorded`.
		const completed = new Set<string>();
		const asking = (name: string): SessionRequirement => ({
			...requirement(name, { remediations: [] }),
			admitPrimary: async () =>
				completed.has(name)
					? "establish"
					: { open: async () => ({ status: 403, body: { error: `${name}_required` } }) },
		});
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:consent", { consent: () => asking("consent") }),
				contributing("test:hold", { hold: () => asking("hold") }),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["consent", "hold"] } } },
		);
		try {
			const deps = {
				userSessionStore: undefined,
				subjectRevocation: undefined,
				requirements: seen.resolver as SessionRequirementResolver,
				acrTable: readAcrTable({}),
				logger: undefined,
				auditSink: undefined,
			};
			const facts = {
				subject: "user-1",
				user: { id: "user-1" },
				claims: { email: "user-1@example.test" },
				authTime: new Date("2026-09-29T00:00:00Z"),
				redirectTo: undefined,
				request: {},
			};
			const first = await admitPrimary(deps, passwordPrimary(facts));
			expect(first).toMatchObject({ outcome: "interrupt", requirement: "consent" });
			if (first.outcome !== "interrupt") throw new Error("unreachable");
			completed.add("consent");
			const second = await resumePrimary(deps, first.continuation, {
				requirement: "consent",
				adds: { amr: [] },
			});
			expect(second).toMatchObject({ outcome: "interrupt", requirement: "hold" });
			if (second.outcome !== "interrupt") throw new Error("unreachable");
			expect(second.continuation.done).toEqual([{ requirement: "consent", adds: { amr: [] } }]);
			// What the second requirement persisted, read back as plain data.
			const persisted = JSON.parse(JSON.stringify(second.continuation)) as PrimaryContinuation;
			completed.add("hold");
			const third = await resumePrimary(deps, persisted, {
				requirement: "hold",
				adds: { amr: [] },
			});
			expect(third.outcome).toBe("establish");
			if (third.outcome !== "establish") throw new Error("unreachable");
			expect(third.establishment.primary.recorded).toEqual({
				amr: ["pwd"],
				authentication: {
					primary: "pwd",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
			});
			expect(third.establishment.primary.claims).toEqual(facts.claims);
		} finally {
			await handle.dispose();
		}
	});
});

describe("a factor's amrValues are held at registration", () => {
	it.each([
		["absent", undefined],
		["a string", "otp"],
		["an empty string", [""]],
		["a primary's marker", ["pwd"]],
		["the federated marker", ["fed"]],
		["mfa itself", ["mfa"]],
	])(
		"refuses a factor whose amrValues are %s as the contribution's failure, not a raw TypeError later",
		async (_label, amrValues) => {
			const broken = defineModule({
				name: "test:factors",
				contributes: {
					mfaFactors: { totp: () => ({ ...factor("totp", [], true), amrValues }) as never },
				},
			});
			const err = await refusal(
				boot([broken, ...stores], { core: { sessionRequirements: { expected: [] } } }),
			);
			expect(err.reason).toBe("contribute-factory-failed");
			expect(err.details).toMatchObject({
				module: "test:factors",
				kind: "mfaFactors",
				name: "totp",
			});
			expect(err.message).toMatch(/amrValues/);
		},
	);
});

describe("the two declaration refusals run the cleanups, and carry what a cleanup threw", () => {
	const closing = defineModule({
		name: "test:closing",
		provides: { closingSlot: () => 1 },
		lifecycle: {
			closingSlot: {
				eager: true,
				cleanup: () => {
					throw new Error("closing failed");
				},
			},
		},
	} as never);

	it("session-requirements-undeclared carries cleanupErrors", async () => {
		const err = await refusal(
			boot([closing, contributing("test:first", { a: () => requirement("a") }), consumer({})], {
				core: { sessionRequirements: { expected: [] } },
			}),
		);
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.details).toMatchObject({
			cleanupErrors: [{ module: "test:closing", componentKey: "closingSlot" }],
		});
	});

	it("session-requirement-missing carries cleanupErrors", async () => {
		const err = await refusal(
			boot([closing], { core: { sessionRequirements: { expected: ["ghost"] } } }),
		);
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			cleanupErrors: [{ module: "test:closing", componentKey: "closingSlot" }],
		});
	});
});

describe("the remediation actions core issues", () => {
	it("issues one branded action per declared route to the module that holds the requirement object it contributed — never through the resolver", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const original = requirement("a", { remediations: ["a.step_up", "a.recover"] });
		const handle = await boot([contributing("test:first", { a: () => original }), consumer(seen)], {
			core: { sessionRequirements: { expected: ["a"] } },
		});
		try {
			expect(issuedRemediationActions(original)).toEqual({
				step_up: { name: "a.step_up", grade: "remediation" },
				recover: { name: "a.recover", grade: "remediation" },
			});
			expect(Object.isFrozen(issuedRemediationActions(original))).toBe(true);
			const projected = seen.resolver?.get("a") as object;
			expect("actions" in projected).toBe(false);
			expect(issuedRemediationActions(projected as SessionRequirement)).toBeUndefined();
		} finally {
			await handle.dispose();
		}
	});
});

describe("the overrides guard reads what the pass reads", () => {
	it("refuses an overrides getter that answers a sessionRequirements entry to the normaliser and nothing to a second read", async () => {
		let reads = 0;
		const evil = {
			name: "test:evil",
			get overrides() {
				reads++;
				return reads === 1 ? { sessionRequirements: { a: () => requirement("a") } } : undefined;
			},
		};
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), evil as never], {
				core: { sessionRequirements: { expected: ["a"] } },
			}),
		);
		expect(err.reason).toBe("session-requirement-kind-guarded");
		expect(err.details).toMatchObject({ channel: "overrides", module: "test:evil" });
	});
});

describe("a factor's values are read once, at registration, and the reach is recomputed from that snapshot alone", () => {
	const mfaWith = (reach: readonly string[]) =>
		authorityModule({ reach: new Set(reach) } as Partial<SessionRequirement>);
	const factorModule = (value: () => unknown) =>
		defineModule({ name: "test:factors", contributes: { mfaFactors: { totp: value as never } } });
	const expected = { core: { sessionRequirements: { expected: ["verifier"] } } };

	it("a getter that answers a valid list at registration and another afterwards: the recomputation reads what was validated", async () => {
		const shifting = (later: readonly string[]) => {
			let reads = 0;
			return factorModule(() => ({
				...factor("totp", [], true),
				get amrValues() {
					reads++;
					return reads === 1 ? ["otp"] : later;
				},
			}));
		};
		// A requirement reaching a value the factor never declared at
		// registration is refused, whatever a later read says.
		const err = await refusal(boot([shifting(["x"]), ...stores, mfaWith(["x", "mfa"])], expected));
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "verifier" });
		expect(err.message).toMatch(/reach/);
		// And the validated list is what the reach is compared with, not a
		// primary's marker a later read answers.
		for (const later of [["pwd"], ["x"]]) {
			const seen: { resolver?: SessionRequirementResolver } = {};
			const handle = await boot(
				[shifting(later), ...stores, mfaWith(["otp", "mfa"]), consumer(seen)],
				expected,
			);
			try {
				expect([...(seen.resolver?.get("verifier")?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
			} finally {
				await handle.dispose();
			}
		}
	});

	it("a mutable list pushed to after registration: the recomputation reads the snapshot", async () => {
		const amrValues = ["otp"];
		let pushedAfter = false;
		// The requirement's own factory runs in the name-keyed pass after the
		// factor registered, and pushes onto the list the factor handed in.
		const late = defineModule({
			name: "test:verifier",
			requires: ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"] as never,
			contributes: {
				sessionRequirements: {
					verifier: (deps: { mfaFactorResolver?: { get(kind: string): unknown } }) => {
						pushedAfter = deps.mfaFactorResolver?.get("totp") !== undefined;
						amrValues.push("x");
						return {
							name: "verifier",
							secondFactorAuthority: true,
							reach: new Set(["otp", "x", "mfa"]),
							stepUpPage: { url: "/verifier", params: {} },
							remediations: ["verifier.step_up"],
							hintKeys: [],
							admit: async () => ({ outcome: "met" as const }),
						};
					},
				},
			},
		} as never);
		const err = await refusal(
			boot(
				[factorModule(() => ({ ...factor("totp", [], true), amrValues })), ...stores, late],
				expected,
			),
		);
		expect(pushedAfter).toBe(true);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "verifier" });
	});

	it("addsMfa is read once too: a getter answering true at registration and false afterwards changes nothing", async () => {
		let reads = 0;
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				factorModule(() => ({
					...factor("totp", ["otp"], true),
					get addsMfa() {
						reads++;
						return reads === 1;
					},
				})),
				...stores,
				mfaWith(["otp", "mfa"]),
				consumer(seen),
			],
			expected,
		);
		try {
			expect([...(seen.resolver?.get("verifier")?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
		} finally {
			await handle.dispose();
		}
	});
});

describe("what could throw raw at the end of stage 4 fails as a BootError", () => {
	it("a factor whose amrValues throw on a later read — the requirement's own getter's — fails as the authority's contribution, not as a raw TypeError", async () => {
		let reads = 0;
		const flaky = defineModule({
			name: "test:factors",
			contributes: {
				mfaFactors: {
					totp: () =>
						({
							...factor("totp", ["otp"], true),
							get amrValues() {
								reads++;
								if (reads > 1) throw new Error("second read");
								return ["otp"];
							},
						}) as never,
				},
			},
		});
		const err = await refusal(
			boot([flaky, ...stores, authorityModule()], {
				core: { sessionRequirements: { expected: ["verifier"] } },
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ kind: "sessionRequirements", name: "verifier" });
	});
});

describe("the reach and the page, checked at the end of stage 4", () => {
	it("refuses a second-factor value in the reach of a requirement that does not declare the second-factor authority, naming the module and the requirement", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:risk", {
						risk: () =>
							requirement("risk", {
								reach: new Set(["otp"]),
								stepUpPage: { url: "/risk", params: {} },
							}),
					}),
				],
				{ core: { sessionRequirements: { expected: ["risk"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.stage).toBe("applyContributions");
		expect(err.details).toMatchObject({
			module: "test:risk",
			kind: "sessionRequirements",
			name: "risk",
		});
		expect(err.message).toMatch(/otp/);
	});

	it("refuses a primary's marker in a reach, a reach without a page, and a page without a reach", async () => {
		for (const [label, over] of [
			["a primary's marker", { reach: new Set(["pwd"]), stepUpPage: { url: "/x", params: {} } }],
			["a reach without a page", { reach: new Set(["risk-ok"]) }],
		] as const) {
			const err = await refusal(
				boot([contributing("test:risk", { risk: () => requirement("risk", over) })], {
					core: { sessionRequirements: { expected: ["risk"] } },
				}),
			);
			expect(err.reason, label).toBe("contribute-factory-failed");
		}
	});

	it("registers a page for a requirement that reaches nothing: a step-up that adds no value still starts somewhere", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:consent", {
					consent: () => requirement("consent", { stepUpPage: { url: "/consent", params: {} } }),
				}),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["consent"] } } },
		);
		try {
			// Resolved once, here, on the configuration's issuer
			// (oauth.jwt.issuer): what every consumer answers or navigates to.
			expect(seen.resolver?.get("consent")?.stepUpPage).toEqual({
				url: "/consent",
				params: {},
				href: "https://auth.test/consent",
			});
			expect(seen.resolver?.get("consent")?.reach.size).toBe(0);
		} finally {
			await handle.dispose();
		}
	});

	it("resolves the page on the issuer of the oauthTokenSettings the composition holds, over the configuration's", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:consent", {
					consent: () => requirement("consent", { stepUpPage: { url: "/consent", params: {} } }),
				}),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["consent"] } } },
			{},
			undefined,
			{ oauthTokenSettings: createTestOAuthTokenSettings({ issuer: "https://slot.test" }) },
		);
		try {
			expect(seen.resolver?.get("consent")?.stepUpPage?.href).toBe("https://slot.test/consent");
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a requirement reaching anything that does not declare the second-factor authority: in this release only the authority adds vouched values to a session", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:risk", {
						risk: () =>
							requirement("risk", {
								reach: new Set(["risk-ok"]),
								stepUpPage: { url: "/risk", params: {} },
							}),
					}),
				],
				{ core: { sessionRequirements: { expected: ["risk"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:risk",
			kind: "sessionRequirements",
			name: "risk",
		});
		expect(err.message).toMatch(/reach/);
		expect(err.message).toMatch(/only the second-factor authority adds vouched values/);
	});

	it("holds a requirement named mfa that does not declare the second-factor authority to the rules of any other: a second-factor value in its reach is refused, and nothing binds it to the MFA ports", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:named", {
						mfa: () =>
							requirement("mfa", {
								reach: new Set(["otp", "mfa"]),
								stepUpPage: { url: "/mfa", params: {} },
							}),
					}),
				],
				{ core: { sessionRequirements: { expected: ["mfa"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "test:named", name: "mfa" });
		expect(err.message).toMatch(/only the second-factor authority may reach/);
		// Reaching nothing, it registers from a module that requires none of
		// the MFA ports, and declares no `mfa.step_up`.
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:named", { mfa: () => requirement("mfa", { remediations: [] }) }),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["mfa"] } } },
		);
		try {
			expect(seen.resolver?.get("mfa")?.secondFactorAuthority).toBe(false);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a requirement whose remediation is not its own route — a fixture declaring oauth.authorize — as the contribution's failure, naming the module", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:risk", {
						risk: () => requirement("risk", { remediations: ["oauth.authorize"] }),
					}),
				],
				{ core: { sessionRequirements: { expected: ["risk"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:risk",
			kind: "sessionRequirements",
			name: "risk",
		});
		expect(err.message).toMatch(/oauth\.authorize/);
	});

	it("refuses a remediation that is a registered action's name even under the requirement's own namespace — a requirement named oauth declaring oauth.authorize — as the contribution's failure", async () => {
		const err = await refusal(
			boot(
				[
					defineModule({
						name: "test:authorize",
						contributes: { admissionActions: { "oauth.authorize": { grade: "use" } } },
					}),
					contributing("test:oauth", {
						oauth: () => requirement("oauth", { remediations: ["oauth.authorize"] }),
					}),
				],
				{ core: { sessionRequirements: { expected: ["oauth"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "test:oauth", name: "oauth" });
		expect(err.message).toMatch(/oauth\.authorize/);
	});

	it("holds the page to the issuer's origin at registration", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:risk", {
						risk: () =>
							requirement("risk", {
								reach: new Set(["risk-ok"]),
								stepUpPage: { url: "https://evil.test/risk", params: {} },
							}),
					}),
				],
				{ core: { sessionRequirements: { expected: ["risk"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toMatch(/origin/);
	});
});

describe("the declaration: core.sessionRequirements.expected", () => {
	it("is required whenever a consumer of admission is installed: none declared refuses the boot, naming the key, what is declared and what is registered", async () => {
		const { core: _none, ...undeclared } = config() as Record<string, unknown>;
		for (const key of ["requires", "optional"] as const) {
			const err = await refusal(
				createApp({
					modules: [contributing("test:first", { a: () => requirement("a") }), consumer({}, key)],
					bootstrapComponents: { config: undeclared, pathResolver: (p: string) => p } as never,
				}),
			);
			expect(err.reason, key).toBe("session-requirements-undeclared");
			expect(err.stage, key).toBe("applyContributions");
			expect(err.details, key).toEqual({
				reason: "session-requirements-undeclared",
				configKey: "core.sessionRequirements.expected",
				declared: undefined,
				registered: ["a"],
				consumedBy: ["test:consumer"],
			});
			expect(err.message, key).toMatch(/core\.sessionRequirements\.expected/);
		}
	});

	it.each([
		["without a consumer", () => []],
		["with a consumer", () => [consumer({})]],
	] as const)(
		"refuses a name it expects that nothing registers, %s: session-requirement-missing, naming the key, the missing name, what is declared and what is registered",
		async (_label, modules) => {
			const err = await refusal(
				boot([...modules()], { core: { sessionRequirements: { expected: ["ghost"] } } }),
			);
			expect(err.reason).toBe("session-requirement-missing");
			expect(err.stage).toBe("applyContributions");
			expect(err.details).toEqual({
				reason: "session-requirement-missing",
				configKey: "core.sessionRequirements.expected",
				missing: ["ghost"],
				declared: ["ghost"],
				registered: [],
			});
			expect(err.message).toMatch(/core\.sessionRequirements\.expected/);
			expect(err.message).toMatch(/ghost/);
		},
	);

	it("names as missing only the expected names nothing registers, in the order they are declared, and says those alone, quoted", async () => {
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), consumer({})], {
				core: { sessionRequirements: { expected: ["mfa", "a", "ghost"] } },
			}),
		);
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			missing: ["mfa", "ghost"],
			declared: ["mfa", "a", "ghost"],
			registered: ["a"],
		});
		expect(err.message).toContain(
			'core.sessionRequirements.expected names ["mfa", "ghost"], which',
		);
	});

	it("names a name declared twice once among the missing", async () => {
		const err = await refusal(
			boot([], { core: { sessionRequirements: { expected: ["ghost", "ghost"] } } }),
		);
		expect(err.details).toMatchObject({ missing: ["ghost"], declared: ["ghost", "ghost"] });
	});

	it("quotes each name it says, so a name with a space in it reads as written", async () => {
		const err = await refusal(boot([], { core: { sessionRequirements: { expected: ["mfa "] } } }));
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({ missing: ["mfa "] });
		expect(err.message).toContain('["mfa "]');
	});

	it("lists what registered in registration order", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:second", { b: () => requirement("b") }),
					contributing("test:first", { a: () => requirement("a") }),
				],
				{ core: { sessionRequirements: { expected: ["b", "a", "ghost"] } } },
			),
		);
		expect(err.details).toMatchObject({ missing: ["ghost"], registered: ["b", "a"] });
	});

	it("is checked for a missing name before a registered one it leaves out: a composition that expects a requirement it did not install is told to install it", async () => {
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), consumer({})], {
				core: { sessionRequirements: { expected: ["mfa"] } },
			}),
		);
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({ missing: ["mfa"], registered: ["a"] });
	});

	it("refuses a registered requirement it does not name while a consumer is installed: session-requirements-undeclared", async () => {
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), consumer({})], {
				core: { sessionRequirements: { expected: [] } },
			}),
		);
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.details).toEqual({
			reason: "session-requirements-undeclared",
			configKey: "core.sessionRequirements.expected",
			declared: [],
			registered: ["a"],
			consumedBy: ["test:consumer"],
		});
	});

	it("boots when it names exactly what registered, nothing included", async () => {
		const seen = {};
		const equal = await boot(
			[contributing("test:first", { a: () => requirement("a") }), consumer(seen)],
			{ core: { sessionRequirements: { expected: ["a"] } } },
		);
		await equal.dispose();
		const none = await boot([consumer(seen)], { core: { sessionRequirements: { expected: [] } } });
		await none.dispose();
	});

	it("refuses a registered requirement it does not name when no consumer is installed too: once written, the key is compared both ways", async () => {
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") })], {
				core: { sessionRequirements: { expected: [] } },
			}),
		);
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.details).toEqual({
			reason: "session-requirements-undeclared",
			configKey: "core.sessionRequirements.expected",
			declared: [],
			registered: ["a"],
			consumedBy: [],
		});
		expect(err.message).toContain('["a"]');
	});

	it("is not required without a consumer: a composition that installs none boots without the key, registered requirements or not", async () => {
		const { core: _none, ...undeclared } = config() as Record<string, unknown>;
		const handle = await createApp({
			modules: [contributing("test:first", { a: () => requirement("a") })],
			bootstrapComponents: { config: undeclared, pathResolver: (p: string) => p } as never,
		});
		await handle.dispose();
	});
});

describe("boot's checks do not act on mfa.mode", () => {
	it.each(["required", "optional"] as const)(
		"boots under mfa.mode = %s with no requirement named mfa and no declaration, when nothing consults admission",
		async (mode) => {
			const { core: _none, ...undeclared } = config({
				mfa: { mode },
			}) as Record<string, unknown>;
			const handle = await createApp({
				modules: [],
				bootstrapComponents: { config: undeclared, pathResolver: (p: string) => p } as never,
			});
			await handle.dispose();
		},
	);

	it.each(["required", "optional"] as const)(
		"boots under mfa.mode = %s with no requirement named mfa beside a consumer, when the declaration expects none",
		async (mode) => {
			const handle = await boot([consumer({})], {
				mfa: { mode },
				core: { sessionRequirements: { expected: [] } },
			});
			await handle.dispose();
		},
	);
});

describe("the second-factor authority is declared, and bound to core's MFA ports, whatever its name", () => {
	const totp = factor("totp", ["otp"], true);
	const factors = defineModule({
		name: "test:factors",
		contributes: { mfaFactors: { totp: () => totp } },
	});
	const expected = { core: { sessionRequirements: { expected: ["verifier"] } } };

	it("accepts an MFA implementation under a name that is not mfa: the declaration, the ports required, the reach the factors' union with mfa, its step_up declared", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot([factors, ...stores, authorityModule(), consumer(seen)], expected);
		try {
			const registered = seen.resolver?.get("verifier");
			expect(registered?.secondFactorAuthority).toBe(true);
			expect([...(registered?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
		} finally {
			await handle.dispose();
		}
	});

	it("reads the reach once, after the pass, and seals it: the resolver answers a read-only snapshot, and a contributor that keeps a mutable Set changes nothing after boot", async () => {
		let reads = 0;
		const live = new Set(["otp", "mfa"]);
		const keeping = defineModule({
			name: "test:verifier",
			requires: ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"] as never,
			contributes: {
				sessionRequirements: {
					verifier: () => ({
						name: "verifier",
						secondFactorAuthority: true,
						get reach() {
							reads++;
							return live;
						},
						stepUpPage: { url: "/verifier", params: {} },
						remediations: ["verifier.step_up"],
						hintKeys: [],
						admit: async () => ({ outcome: "met" as const }),
					}),
				},
			},
		} as never);
		const seen: { resolver?: SessionRequirementResolver } = {};
		// The factors register after the requirement: a reach read at
		// registration would be compared before they did.
		const handle = await boot([keeping, ...stores, consumer(seen), factors], expected);
		try {
			expect(reads).toBe(1);
			const registered = seen.resolver?.get("verifier");
			expect([...(registered?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
			live.add("hwk");
			live.delete("otp");
			expect([...(registered?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
			const [entry] = Array.from(seen.resolver?.entries() ?? []);
			expect([...(entry?.[1].reach ?? [])].sort()).toEqual(["mfa", "otp"]);
			expect(reads).toBe(1);
			const sealed = registered?.reach as Set<string>;
			expect(Object.isFrozen(sealed)).toBe(true);
			expect("add" in sealed).toBe(false);
			expect(() => sealed.add("x")).toThrow(TypeError);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses the second-factor authority from a module that does not require the three ports, naming the module", async () => {
		const err = await refusal(
			boot([factors, ...stores, authorityModule({}, ["mfaFactorResolver"])], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:verifier",
			kind: "sessionRequirements",
			name: "verifier",
		});
		expect(err.message).toMatch(/second-factor authority/);
		expect(err.message).toMatch(/mfaFactorStore/);
	});

	it("refuses the second-factor authority whose reach is not the set core recomputes from the factors", async () => {
		const err = await refusal(
			boot([factors, ...stores, authorityModule({ reach: new Set(["otp"]) })], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ name: "verifier" });
		expect(err.message).toMatch(/reach/);
	});

	it("refuses the second-factor authority that does not declare its own step_up remediation", async () => {
		const err = await refusal(
			boot([factors, ...stores, authorityModule({ remediations: ["verifier.other"] })], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toMatch(/verifier\.step_up/);
	});

	it("refuses two requirements that declare the second-factor authority — duplicate-second-factor-authority, naming each with its module in registration order — after the cleanups", async () => {
		const closing = defineModule({
			name: "test:closing",
			provides: { closingSlot: () => 1 },
			lifecycle: {
				closingSlot: {
					eager: true,
					cleanup: () => {
						throw new Error("closing failed");
					},
				},
			},
		} as never);
		const err = await refusal(
			boot(
				[
					closing,
					factors,
					...stores,
					authorityModule(),
					authorityModule({}, undefined, "keys", "test:keys"),
				],
				{ core: { sessionRequirements: { expected: ["verifier", "keys"] } } },
			),
		);
		expect(err.reason).toBe("duplicate-second-factor-authority");
		expect(err.stage).toBe("applyContributions");
		expect(err.details).toEqual({
			reason: "duplicate-second-factor-authority",
			requirements: [
				{ name: "verifier", module: "test:verifier" },
				{ name: "keys", module: "test:keys" },
			],
			cleanupErrors: [
				expect.objectContaining({ module: "test:closing", componentKey: "closingSlot" }),
			],
		});
		expect(err.message).toContain('"verifier" (module "test:verifier")');
		expect(err.message).toContain('"keys" (module "test:keys")');
		expect(err.message).toMatch(/at most one/);
		expect(err.message).toContain("install only one of the modules that contribute them");
	});

	it("refuses a second declaration even when either's reach or ports are wrong: the duplicate is what the composition must fix first", async () => {
		const err = await refusal(
			boot(
				[
					factors,
					...stores,
					authorityModule({ reach: new Set(["otp"]) }),
					authorityModule({}, ["mfaFactorResolver"], "keys", "test:keys"),
				],
				{ core: { sessionRequirements: { expected: ["verifier", "keys"] } } },
			),
		);
		expect(err.reason).toBe("duplicate-second-factor-authority");
	});

	it("refuses a declaration that is neither true, false nor absent as the contribution's failure, naming the module", async () => {
		for (const declared of ["yes", 1, null]) {
			const err = await refusal(
				boot(
					[
						contributing("test:risk", {
							risk: () => ({
								...requirement("risk"),
								secondFactorAuthority: declared as never,
							}),
						}),
					],
					{ core: { sessionRequirements: { expected: ["risk"] } } },
				),
			);
			expect(err.reason, String(declared)).toBe("contribute-factory-failed");
			expect(err.details, String(declared)).toMatchObject({
				module: "test:risk",
				kind: "sessionRequirements",
				name: "risk",
			});
			expect(err.message, String(declared)).toMatch(
				/secondFactorAuthority must be true, false or absent/,
			);
		}
	});

	it("boots one authority beside requirements that do not declare it, and binds only the one that does", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				factors,
				...stores,
				contributing("test:named", { mfa: () => requirement("mfa", { remediations: [] }) }),
				authorityModule(),
				consumer(seen),
			],
			{ core: { sessionRequirements: { expected: ["mfa", "verifier"] } } },
		);
		try {
			expect(
				[...(seen.resolver?.entries() ?? [])].map(([name, r]) => [name, r.secondFactorAuthority]),
			).toEqual([
				["mfa", false],
				["verifier", true],
			]);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the session_requirements_registered boot line", () => {
	it("says once at info, in order, each requirement's name, its module and its remediations, when a consumer or a requirement is present", async () => {
		const { logger, lines } = recordingLogger();
		const handle = await boot(
			[
				contributing("test:second", { b: () => requirement("b", { remediations: [] }) }),
				contributing("test:first", { a: () => requirement("a") }),
				consumer({}),
			],
			{ core: { sessionRequirements: { expected: ["a", "b"] } } },
			{},
			logger,
		);
		await handle.dispose();
		const registered = lines.filter((line) => line.message === "session_requirements_registered");
		expect(registered).toEqual([
			{
				level: "info",
				message: "session_requirements_registered",
				fields: {
					requirements: [
						{ name: "b", module: "test:second", remediations: [], secondFactorAuthority: false },
						{
							name: "a",
							module: "test:first",
							remediations: ["a.step_up"],
							secondFactorAuthority: false,
						},
					],
				},
			},
		]);
	});

	it("says which requirement declares the second-factor authority, whatever its name, so the log tells the authority from a requirement merely named mfa", async () => {
		const { logger, lines } = recordingLogger();
		const handle = await boot(
			[
				defineModule({
					name: "test:factors",
					contributes: { mfaFactors: { totp: () => factor("totp", ["otp"], true) } },
				}),
				...stores,
				contributing("test:named", { mfa: () => requirement("mfa", { remediations: [] }) }),
				authorityModule(),
			],
			{ core: { sessionRequirements: { expected: ["mfa", "verifier"] } } },
			{},
			logger,
		);
		await handle.dispose();
		const [registered] = lines.filter((line) => line.message === "session_requirements_registered");
		expect(registered?.fields).toEqual({
			requirements: [
				{ name: "mfa", module: "test:named", remediations: [], secondFactorAuthority: false },
				{
					name: "verifier",
					module: "test:verifier",
					remediations: ["verifier.step_up"],
					secondFactorAuthority: true,
				},
			],
		});
	});

	it("says nothing when neither a consumer nor a requirement is installed", async () => {
		const { logger, lines } = recordingLogger();
		const handle = await boot([], {}, {}, logger);
		await handle.dispose();
		expect(lines.filter((line) => line.message === "session_requirements_registered")).toEqual([]);
	});
});

describe("stage 4: the reach without mfa, a refusal's cleanups, every consumer named", () => {
	it("recomputes the authority's reach without mfa when no factor adds it", async () => {
		const plain = defineModule({
			name: "test:factors",
			contributes: { mfaFactors: { totp: () => factor("totp", ["otp"], false) } },
		});
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot([plain, ...stores, authorityModule(), consumer(seen)], {
			core: { sessionRequirements: { expected: ["verifier"] } },
		});
		try {
			expect([...(seen.resolver?.get("verifier")?.reach ?? [])]).toEqual(["otp"]);
		} finally {
			await handle.dispose();
		}
	});

	it("a requirement's refusal at the end of stage 4 runs the cleanups and carries what one threw", async () => {
		const closing = defineModule({
			name: "test:closing",
			provides: { closingSlot: () => 1 },
			lifecycle: {
				closingSlot: {
					eager: true,
					cleanup: () => {
						throw new Error("closing failed");
					},
				},
			},
		} as never);
		const err = await refusal(
			boot(
				[
					closing,
					contributing("test:risk", {
						risk: () =>
							requirement("risk", {
								reach: new Set(["risk-ok"]),
								stepUpPage: { url: "/risk", params: {} },
							}),
					}),
				],
				{ core: { sessionRequirements: { expected: ["risk"] } } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:risk",
			name: "risk",
			cleanupErrors: [{ module: "test:closing", componentKey: "closingSlot" }],
		});
	});

	it("names every consumer when more than one consults admission and the declaration disagrees", async () => {
		const other = defineModule({
			name: "test:consumer-2",
			requires: ["sessionRequirementResolver"] as never,
		} as never);
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), consumer({}), other], {
				core: { sessionRequirements: { expected: [] } },
			}),
		);
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.message).toMatch(/modules \[test:consumer, test:consumer-2\]/);
	});
});
