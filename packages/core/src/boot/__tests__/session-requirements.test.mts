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
 * `sessionRequirementResolver`, booted through `createApp` (the
 * session-admission ADR's D3, D7): registration in init order and the
 * branded projection; the three refusals that keep a requirement from being
 * switched off from behind the consumers; the checks at the end of stage 4 —
 * the reach and the page, the declaration `sessionRequirements.expected`
 * compared as a set, `mfa.mode` asking for a requirement that is not
 * installed, and the name `mfa` bound to core's MFA ports; and the one boot
 * line.
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
import type {
	PrimaryContinuation,
	SessionRequirement,
	SessionRequirementResolver,
} from "#/session-admission/requirement.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const config = (over: Record<string, unknown> = {}) => ({
	...makeValidCoreConfig(),
	sessionRequirements: { expected: [] },
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
) =>
	createApp({
		modules,
		bootstrapComponents: {
			config: config(over),
			pathResolver: (p: string) => p,
			...(logger === undefined ? {} : { logger }),
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

const hostCollector = () => ({
	kind: "name-keyed" as const,
	register: () => {},
	replace: () => {},
	get: () => undefined,
	entries: () => [][Symbol.iterator](),
});

describe("the sessionRequirements kind and sessionRequirementResolver (D3)", () => {
	it("registers each requirement under its key in init order, projects them through the resolver, and admitSession accepts that resolver", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:second", { b: () => requirement("b") }),
				contributing("test:first", { a: () => requirement("a") }),
				consumer(seen),
			],
			{ sessionRequirements: { expected: ["a", "b"] } },
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
					action: { name: "test.use", grade: "use" },
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
				sessionRequirements: { expected: ["a"] },
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
				sessionRequirements: { expected: ["a"] },
			}),
		);
		expect(misnamed.reason).toBe("contribute-factory-failed");
		expect(misnamed.message).toMatch(/name/);
	});
});

describe("the three channels, three refusals (D3)", () => {
	it("refuses an override of sessionRequirements: session-requirement-kind-guarded", async () => {
		const overriding = defineModule({
			name: "test:overriding",
			overrides: { sessionRequirements: { a: () => requirement("a") } },
		} as never);
		const err = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), overriding], {
				sessionRequirements: { expected: ["a"] },
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

describe("a requirement that reaches nothing completes an interruption with an empty addition (D5)", () => {
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
			{ sessionRequirements: { expected: ["consent", "hold"] } },
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

describe("a factor's amrValues are held at registration (D3)", () => {
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
				boot([broken, ...stores], { sessionRequirements: { expected: [] } }),
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

describe("the two declaration refusals run the cleanups, and carry what a cleanup threw (D7)", () => {
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
			boot([closing, consumer({})], { sessionRequirements: { expected: ["ghost"] } }),
		);
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.details).toMatchObject({
			cleanupErrors: [{ module: "test:closing", componentKey: "closingSlot" }],
		});
	});

	it("session-requirement-missing carries cleanupErrors", async () => {
		const err = await refusal(boot([closing], { mfa: { mode: "required" } }));
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			cleanupErrors: [{ module: "test:closing", componentKey: "closingSlot" }],
		});
	});
});

describe("the remediation actions core issues (D4)", () => {
	it("hands each registered copy one branded action per declared route, which the resolver projects", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot(
			[
				contributing("test:first", {
					a: () => requirement("a", { remediations: ["a.step_up", "a.recover"] }),
				}),
				consumer(seen),
			],
			{ sessionRequirements: { expected: ["a"] } },
		);
		try {
			expect(seen.resolver?.get("a")?.actions).toEqual({
				step_up: { name: "a.step_up", grade: "remediation" },
				recover: { name: "a.recover", grade: "remediation" },
			});
			expect(Object.isFrozen(seen.resolver?.get("a")?.actions)).toBe(true);
		} finally {
			await handle.dispose();
		}
	});
});

describe("the reach and the page, read once at the end of stage 4 (D3)", () => {
	it("refuses a second-factor value in the reach of a requirement not named mfa, naming the module and the requirement", async () => {
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
				{ sessionRequirements: { expected: ["risk"] } },
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
					sessionRequirements: { expected: ["risk"] },
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
			{ sessionRequirements: { expected: ["consent"] } },
		);
		try {
			expect(seen.resolver?.get("consent")?.stepUpPage).toEqual({ url: "/consent", params: {} });
			expect(seen.resolver?.get("consent")?.reach.size).toBe(0);
		} finally {
			await handle.dispose();
		}
	});

	it("refuses a requirement reaching anything under any name but mfa: in this release only the MFA requirement adds vouched values to a session", async () => {
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
				{ sessionRequirements: { expected: ["risk"] } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:risk",
			kind: "sessionRequirements",
			name: "risk",
		});
		expect(err.message).toMatch(/reach/);
		expect(err.message).toMatch(/mfa/);
	});

	it("refuses a requirement whose remediation is not its own route — a fixture declaring oauth.authorize — as the contribution's failure, naming the module", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:risk", {
						risk: () => requirement("risk", { remediations: ["oauth.authorize"] }),
					}),
				],
				{ sessionRequirements: { expected: ["risk"] } },
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

	it("refuses a remediation that is a consumer's action even under the requirement's own namespace — a requirement named oauth declaring oauth.authorize — as the contribution's failure", async () => {
		const err = await refusal(
			boot(
				[
					contributing("test:oauth", {
						oauth: () => requirement("oauth", { remediations: ["oauth.authorize"] }),
					}),
				],
				{ sessionRequirements: { expected: ["oauth"] } },
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
				{ sessionRequirements: { expected: ["risk"] } },
			),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toMatch(/origin/);
	});
});

describe("the declaration: sessionRequirements.expected (D7)", () => {
	it("is required whenever a consumer of admission is installed: none declared refuses the boot, naming the key, what is declared and what is registered", async () => {
		const { sessionRequirements: _none, ...undeclared } = config() as Record<string, unknown>;
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
				configKey: "sessionRequirements.expected",
				declared: undefined,
				registered: ["a"],
				consumedBy: ["test:consumer"],
			});
			expect(err.message, key).toMatch(/sessionRequirements\.expected/);
		}
	});

	it("must equal what is registered, in either direction", async () => {
		const seen = {};
		const declaredNotRegistered = await refusal(
			boot([consumer(seen)], { sessionRequirements: { expected: ["a"] } }),
		);
		expect(declaredNotRegistered.reason).toBe("session-requirements-undeclared");
		expect(declaredNotRegistered.details).toMatchObject({ declared: ["a"], registered: [] });
		const registeredNotDeclared = await refusal(
			boot([contributing("test:first", { a: () => requirement("a") }), consumer(seen)], {
				sessionRequirements: { expected: [] },
			}),
		);
		expect(registeredNotDeclared.reason).toBe("session-requirements-undeclared");
		expect(registeredNotDeclared.details).toMatchObject({ declared: [], registered: ["a"] });
		const equal = await boot(
			[contributing("test:first", { a: () => requirement("a") }), consumer(seen)],
			{ sessionRequirements: { expected: ["a"] } },
		);
		await equal.dispose();
		const none = await boot([consumer(seen)], { sessionRequirements: { expected: [] } });
		await none.dispose();
	});

	it("is not required without a consumer: a composition that installs none boots without the key, registered requirements or not", async () => {
		const { sessionRequirements: _none, ...undeclared } = config() as Record<string, unknown>;
		const handle = await createApp({
			modules: [contributing("test:first", { a: () => requirement("a") })],
			bootstrapComponents: { config: undeclared, pathResolver: (p: string) => p } as never,
		});
		await handle.dispose();
	});
});

describe("mfa.mode asks for a requirement that is not installed (D7)", () => {
	it.each(["required", "optional"] as const)(
		"refuses mfa.mode = %s with no requirement named mfa: session-requirement-missing",
		async (mode) => {
			const err = await refusal(boot([], { mfa: { mode } }));
			expect(err.reason).toBe("session-requirement-missing");
			expect(err.stage).toBe("applyContributions");
			expect(err.details).toEqual({
				reason: "session-requirement-missing",
				configKey: "mfa.mode",
				mode,
				requirement: "mfa",
			});
			expect(err.message).toMatch(/mfa\.mode = "off"/);
		},
	);

	it("boots under mfa.mode = off with no requirement", async () => {
		const handle = await boot([], { mfa: { mode: "off" } });
		await handle.dispose();
	});

	it("is checked before the declaration: a composition that asks for MFA without the module is told to install it, not to fix the list", async () => {
		const err = await refusal(
			boot([consumer({})], {
				mfa: { mode: "required" },
				sessionRequirements: { expected: ["mfa"] },
			}),
		);
		expect(err.reason).toBe("session-requirement-missing");
	});
});

describe("the name mfa is reserved, and bound to core's MFA ports (D3)", () => {
	const totp = factor("totp", ["otp"], true);
	const factors = defineModule({
		name: "test:factors",
		contributes: { mfaFactors: { totp: () => totp } },
	});
	/** An MFA implementation: requires the three ports, reaches what the factors reach, declares mfa.step_up. */
	const mfaModule = (over: Partial<SessionRequirement> = {}, requires?: readonly string[]) =>
		defineModule({
			name: "test:mfa",
			requires: (requires ?? [
				"mfaFactorResolver",
				"mfaFactorStore",
				"mfaTransactionStore",
			]) as never,
			contributes: {
				sessionRequirements: {
					mfa: (deps: {
						mfaFactorResolver?: { entries(): Iterable<readonly [string, MfaFactor]> };
					}) => ({
						name: "mfa",
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
						stepUpPage: { url: "/mfa", params: {} },
						remediations: ["mfa.step_up"],
						hintKeys: [],
						admit: async () => ({ outcome: "met" as const }),
						...over,
					}),
				},
			},
		} as never);
	const expected = { sessionRequirements: { expected: ["mfa"] }, mfa: { mode: "required" } };

	it("accepts an MFA implementation: the ports required, the reach the factors' union with mfa, mfa.step_up declared", async () => {
		const seen: { resolver?: SessionRequirementResolver } = {};
		const handle = await boot([factors, ...stores, mfaModule(), consumer(seen)], expected);
		try {
			expect([...(seen.resolver?.get("mfa")?.reach ?? [])].sort()).toEqual(["mfa", "otp"]);
		} finally {
			await handle.dispose();
		}
	});

	it("reads the reach once, after the pass, and seals it: the resolver answers a read-only snapshot, and a contributor that keeps a mutable Set changes nothing after boot", async () => {
		let reads = 0;
		const live = new Set(["otp", "mfa"]);
		const keeping = defineModule({
			name: "test:mfa",
			requires: ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"] as never,
			contributes: {
				sessionRequirements: {
					mfa: () => ({
						name: "mfa",
						get reach() {
							reads++;
							return live;
						},
						stepUpPage: { url: "/mfa", params: {} },
						remediations: ["mfa.step_up"],
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
			const registered = seen.resolver?.get("mfa");
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

	it("refuses a requirement named mfa from a module that does not require the three ports, naming the module", async () => {
		const err = await refusal(
			boot([factors, ...stores, mfaModule({}, ["mfaFactorResolver"])], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			module: "test:mfa",
			kind: "sessionRequirements",
			name: "mfa",
		});
		expect(err.message).toMatch(/mfaFactorStore/);
	});

	it("refuses a requirement named mfa whose reach is not the set core recomputes from the factors", async () => {
		const err = await refusal(
			boot([factors, ...stores, mfaModule({ reach: new Set(["otp"]) })], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toMatch(/reach/);
	});

	it("refuses a requirement named mfa that does not declare mfa.step_up", async () => {
		const err = await refusal(
			boot([factors, ...stores, mfaModule({ remediations: ["mfa.other"] })], expected),
		);
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.message).toMatch(/mfa\.step_up/);
	});
});

describe("the boot line (D3)", () => {
	it("says once at info, in order, each requirement's name, its module and its remediations, when a consumer or a requirement is present", async () => {
		const { logger, lines } = recordingLogger();
		const handle = await boot(
			[
				contributing("test:second", { b: () => requirement("b", { remediations: [] }) }),
				contributing("test:first", { a: () => requirement("a") }),
				consumer({}),
			],
			{ sessionRequirements: { expected: ["a", "b"] } },
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
						{ name: "b", module: "test:second", remediations: [] },
						{ name: "a", module: "test:first", remediations: ["a.step_up"] },
					],
				},
			},
		]);
	});

	it("says nothing when neither a consumer nor a requirement is installed", async () => {
		const { logger, lines } = recordingLogger();
		const handle = await boot([], {}, {}, logger);
		await handle.dispose();
		expect(lines.filter((line) => line.message === "session_requirements_registered")).toEqual([]);
	});
});
