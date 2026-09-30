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
 * Establishment (the session-admission ADR's D5): `admitPrimary` asks the
 * requirements that interrupt a login, in order; `resumePrimary` composes
 * what every completed requirement added and asks each one not yet done;
 * `establishWithoutAsking` builds a federated login's establishment from
 * the federation's own facts; the `Establishment` brand; and the answer of
 * an interruption, validated before the route sees it.
 */

import { describe, expect, it } from "vitest";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitPrimary,
	establishWithoutAsking,
	isEstablishment,
	isInterruptAdmission,
	passwordPrimary,
	resumePrimary,
} from "#/session-admission/admit.mjs";
import { continuationOf } from "#/session-admission/primary.mjs";
import type {
	AdmissionDeps,
	InterruptionAnswer,
	PrimaryAdmission,
	PrimaryAuthentication,
	PrimaryContinuation,
	RequirementInterruption,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";

const NOW = new Date("2026-09-28T12:00:00Z");

/** The facts a password login produces. */
const facts = () => ({
	subject: "user-1",
	user: { id: "user-1", groups: ["staff"] },
	claims: { email: "user-1@example.test", emailVerified: true, groups: ["staff"] },
	authTime: NOW,
	redirectTo: "/after",
	request: { ip: "198.51.100.7", userAgent: "test" },
});

/** The primary as `passwordPrimary` builds it from the facts. */
const primary = (over: Partial<PrimaryAuthentication> = {}): PrimaryAuthentication => ({
	...facts(),
	recorded: {
		amr: ["pwd"],
		authentication: {
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		},
	},
	// What core derives from the facts' user: no witness, no address.
	enrollmentFacts: { witness: "not_enrolled", mailAddress: "none" },
	...over,
});

const answer = (over: Partial<InterruptionAnswer["body"]> = {}): InterruptionAnswer => ({
	status: 403,
	body: { error: "mfa_required", transaction: "dHgtMQ", expires_in: 600, ...over },
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

/** A requirement that answers `answerWith` at establishment, recording what it was asked about. */
const asking = (
	name: string,
	answerWith: (primary: PrimaryAuthentication) => "establish" | RequirementInterruption,
	over: Partial<SessionRequirement> = {},
): SessionRequirement & { readonly asked: PrimaryAuthentication[] } => {
	const asked: PrimaryAuthentication[] = [];
	// What a fixture may add at completion is within its reach (the
	// session-admission ADR's D5): the one that declares the second-factor
	// authority — under a name that is not `mfa` — reaches the second-factor
	// values, the risk one its own.
	const reach = { verifier: ["otp", "hwk", "mfa"], risk: ["risk-ok"] }[name] ?? [];
	return {
		name,
		secondFactorAuthority: name === "verifier",
		reach: new Set(reach),
		stepUpPage: reach.length === 0 ? undefined : { url: `/${name}`, params: {} },
		remediations: [],
		hintKeys: ["enrollable", "email_proof"],
		admit: async () => ({ outcome: "met" }),
		admitPrimary: async (p) => {
			asked.push(p);
			return answerWith(p);
		},
		asked,
		...over,
	};
};

const interrupting = (
	open: RequirementInterruption["open"] = async () => answer(),
): RequirementInterruption => ({
	open,
});

const deps = (requirements: SessionRequirement[], logger?: Logger): AdmissionDeps => ({
	userSessionStore: undefined,
	subjectRevocation: undefined,
	// The mechanics over a reaching `risk` fixture; the boot-shaped case is in
	// boot/__tests__/session-requirements.test.mts.
	requirements: resolverForTests(requirements, {
		allowAnyReach: true,
		issuer: "https://auth.test",
	}),
	acrTable: readAcrTable({}),
	logger,
	auditSink: undefined,
	now: () => NOW,
});

describe("admitPrimary — the login asks before anything is written", () => {
	it("establishes when no requirement interrupts, over the primary passwordPrimary built from the route's facts, branded", async () => {
		const source = facts();
		const built = passwordPrimary(source);
		expect(built).toEqual(primary());
		expect(Object.isFrozen(built)).toBe(true);
		(source.user as Record<string, unknown>).id = "someone-else";
		expect(built.user.id).toBe("user-1");
		const admission = await admitPrimary(deps([]), built);
		expect(admission.outcome).toBe("establish");
		if (admission.outcome !== "establish") throw new Error("unreachable");
		expect(isEstablishment(admission.establishment)).toBe(true);
		expect(Object.isFrozen(admission.establishment)).toBe(true);
		expect(admission.establishment.primary).toBe(built);
	});

	it("carries the route's claims — extractUserClaims(user) — as a frozen copy sharing nothing with the facts, and refuses facts without them", () => {
		const source = facts();
		const built = passwordPrimary(source);
		expect(built.claims).toEqual(source.claims);
		expect(built.claims).not.toBe(source.claims);
		expect(Object.isFrozen(built.claims)).toBe(true);
		(source.claims.groups as string[]).push("admin");
		expect(built.claims.groups).toEqual(["staff"]);
		for (const claims of [undefined, null, "email", 7, ["email"]]) {
			expect(
				() => passwordPrimary({ ...facts(), claims: claims as never }),
				JSON.stringify(claims),
			).toThrow(RangeError);
		}
	});

	it("passwordPrimary records pwd alone: a route cannot hand in an amr or an mfaAt, and its facts are checked", () => {
		expect(
			passwordPrimary({ ...facts(), recorded: { amr: ["pwd", "otp", "mfa"] } } as never).recorded,
		).toEqual(primary().recorded);
		for (const bad of [
			undefined,
			{ ...facts(), subject: "" },
			{ ...facts(), user: "alice" },
			{ ...facts(), authTime: "now" },
			{ ...facts(), request: undefined },
		]) {
			expect(() => passwordPrimary(bad as never), JSON.stringify(bad)).toThrow(RangeError);
		}
	});

	it("asks each requirement with admitPrimary in registration order, skipping those without, and the first interruption wins", async () => {
		const asked: string[] = [];
		const first = asking("first", () => {
			asked.push("first");
			return "establish";
		});
		const silent: SessionRequirement = {
			name: "silent",
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
		};
		const second = asking("second", () => {
			asked.push("second");
			return interrupting();
		});
		const third = asking("third", () => {
			asked.push("third");
			return interrupting();
		});
		const admission = await admitPrimary(
			deps([first, silent, second, third]),
			passwordPrimary(facts()),
		);
		expect(asked).toEqual(["first", "second"]);
		expect(admission).toMatchObject({
			outcome: "interrupt",
			requirement: "second",
			continuation: continuationOf(primary(), [], "second"),
		});
		expect(first.asked[0]).toEqual(primary());
	});

	it("hands each requirement the frozen primary core built, which shares nothing with the route's facts", async () => {
		const watching = asking("watch", () => "establish");
		const source = facts();
		const built = passwordPrimary(source);
		await admitPrimary(deps([watching]), built);
		expect(watching.asked[0]).toBe(built);
		expect(Object.isFrozen(watching.asked[0])).toBe(true);
		expect(watching.asked[0]?.user).not.toBe(source.user);
	});

	it("answers unavailable, logged once, when a requirement throws or answers something that is not establish or an interruption", async () => {
		const { logger, lines } = recordingLogger();
		const failing = asking("risk", () => {
			throw new Error("scorer down");
		});
		expect(await admitPrimary(deps([failing], logger), passwordPrimary(facts()))).toEqual({
			outcome: "unavailable",
			store: "risk",
		});
		expect(lines).toHaveLength(1);
		expect(lines[0]).toMatchObject({
			level: "error",
			message: "session_admission_unavailable",
			fields: { store: "risk", phase: "establishment" },
		});
		lines.length = 0;
		for (const odd of [undefined, null, "later", "Establish", 7, { open: "x" }, {}, []]) {
			const answering = asking("odd", () => odd as never);
			expect(
				await admitPrimary(deps([answering], logger), passwordPrimary(facts())),
				String(odd),
			).toEqual({
				outcome: "unavailable",
				store: "odd",
			});
		}
		expect(lines).toHaveLength(8);
	});

	it("refuses, before asking anything, a resolver it does not know and a primary no core builder made", async () => {
		const watching = asking("watch", () => "establish");
		await expect(
			admitPrimary({ ...deps([watching]), requirements: {} as never }, passwordPrimary(facts())),
		).rejects.toThrow(RangeError);
		// Shaped like one, even equal to one, is not one core built.
		for (const bad of [undefined, primary(), { ...passwordPrimary(facts()) }]) {
			await expect(admitPrimary(deps([watching]), bad as never)).rejects.toThrow(RangeError);
		}
		expect(watching.asked).toEqual([]);
	});
});

describe("the interruption's answer — validated before the route sees it", () => {
	const interrupt = async (
		open: RequirementInterruption["open"],
		hintKeys: readonly string[] = ["enrollable", "email_proof"],
	): Promise<Extract<PrimaryAdmission, { outcome: "interrupt" }>> => {
		const requirement = asking("verifier", () => interrupting(open), { hintKeys });
		const admission = await admitPrimary(deps([requirement]), passwordPrimary(facts()));
		if (admission.outcome !== "interrupt") throw new Error("expected an interruption");
		return admission;
	};

	it("opens the requirement's ceremony with the session id and the continuation core built — what the requirement persists — and answers a frozen copy of the body", async () => {
		const opened: string[] = [];
		let received: unknown;
		const admission = await interrupt(async (sessionId, continuation) => {
			opened.push(sessionId);
			received = continuation;
			return answer({ hints: { enrollable: ["totp"], email_proof: false } });
		});
		const result = await admission.open("express-1");
		expect(opened).toEqual(["express-1"]);
		expect(received).toBe(admission.continuation);
		expect(received).toEqual(continuationOf(primary(), [], "verifier"));
		expect(result).toEqual({
			status: 403,
			body: {
				error: "mfa_required",
				transaction: "dHgtMQ",
				expires_in: 600,
				hints: { enrollable: ["totp"], email_proof: false },
			},
		});
		expect(Object.isFrozen(result)).toBe(true);
		expect(Object.isFrozen(result.body)).toBe(true);
	});

	it("caps the hint grammar: a number is an integer in [0, 86400], a list holds at most 16 tokens, a transaction at most 128 base64url characters", async () => {
		const sixteen = Array.from({ length: 16 }, (_, i) => `f${i}`);
		const ok = await interrupt(async () =>
			answer({ transaction: "a".repeat(128), hints: { email_proof: 86400, enrollable: sixteen } }),
		);
		expect((await ok.open("s")).body.hints).toEqual({ email_proof: 86400, enrollable: sixteen });
		const zero = await interrupt(async () => answer({ hints: { email_proof: 0 } }));
		expect((await zero.open("s")).body.hints).toEqual({ email_proof: 0 });
		for (const [label, body] of [
			["a number above 86400", answer({ hints: { email_proof: 86401 } })],
			["a negative number", answer({ hints: { email_proof: -1 } })],
			["a fraction", answer({ hints: { email_proof: 1.5 } })],
			["a list of 17", answer({ hints: { enrollable: [...sixteen, "f16"] } })],
			["a transaction of 129", answer({ transaction: "a".repeat(129) })],
		] as const) {
			const admission = await interrupt(async () => body);
			await expect(admission.open("s"), label).rejects.toThrow(RangeError);
		}
	});

	it("reads the answer's body once: a getter answering a valid body to the check and another afterwards changes nothing", async () => {
		let reads = 0;
		const admission = await interrupt(
			async () =>
				({
					status: 403,
					get body() {
						reads++;
						return reads === 1
							? { error: "mfa_required" }
							: { error: "mfa_required", user: { id: "user-1" } };
					},
				}) as never,
		);
		expect(await admission.open("s")).toEqual({ status: 403, body: { error: "mfa_required" } });
	});

	it("refuses an own __proto__ key in the body like every other key the shape does not admit", async () => {
		// A key named "__proto__" assigned into a plain object sets its
		// prototype instead of an own key, so a copy-then-list check misses it.
		const body = JSON.parse('{"error":"mfa_required","__proto__":{"user":"user-1"}}');
		const admission = await interrupt(async () => ({ status: 403, body }) as never);
		await expect(admission.open("s")).rejects.toThrow(
			/whose body carries "__proto__", which the body's shape does not admit/,
		);
	});

	it("refuses an answer that is not an object, naming the requirement", async () => {
		for (const value of ["403", null, 7]) {
			const admission = await interrupt(async () => value as never);
			await expect(admission.open("s"), String(value)).rejects.toThrow(
				/requirement "verifier" answered an interruption that is not an object/,
			);
		}
	});

	it("refuses a session id that is not a non-empty string, before opening", async () => {
		let opened = 0;
		const admission = await interrupt(async () => {
			opened++;
			return answer();
		});
		await expect(admission.open("")).rejects.toThrow(RangeError);
		await expect(admission.open(7 as never)).rejects.toThrow(RangeError);
		expect(opened).toBe(0);
	});

	it("lets a throw from the requirement's open through as it is: an outage the route answers 503", async () => {
		const failure = new Error("transaction store down");
		const admission = await interrupt(async () => {
			throw failure;
		});
		await expect(admission.open("express-1")).rejects.toBe(failure);
	});

	it.each([
		["a status that is not 403", { status: 200, body: { error: "mfa_required" } }],
		["no body", { status: 403 }],
		["an error that is not a well-formed error code", answer({ error: 'bad "quote"' })],
		["an empty error", answer({ error: "" })],
		["a transaction that is not base64url", answer({ transaction: "tx+1/=" })],
		["a transaction that is not a string", answer({ transaction: 7 as never })],
		["an expires_in that is not a positive integer", answer({ expires_in: 0 })],
		["a fractional expires_in", answer({ expires_in: 1.5 })],
		["a user snapshot", { status: 403, body: { error: "mfa_required", user: { id: "user-1" } } }],
		["a sub", { status: 403, body: { error: "mfa_required", sub: "user-1" } }],
		["a sid", { status: 403, body: { error: "mfa_required", sid: "sid-1" } }],
		["any other key", { status: 403, body: { error: "mfa_required", extra: 1 } }],
		["a hint key the requirement did not declare", answer({ hints: { user_email: "x" } })],
		["a hint value carrying an address", answer({ hints: { enrollable: "alice@example.com" } })],
		["a hint list carrying an address", answer({ hints: { enrollable: ["totp", "a@b.c"] } })],
		["a hint value over 64 characters", answer({ hints: { enrollable: `x${"y".repeat(64)}` } })],
		["a hint value with a space", answer({ hints: { enrollable: "totp or email" } })],
		["a hint value with a capital", answer({ hints: { enrollable: "Totp" } })],
		["a hint value that is a URL", answer({ hints: { enrollable: "https://x.test/mfa" } })],
		["a hint value with a control character", answer({ hints: { enrollable: "a\nb" } })],
		["a hint that is not a finite number", answer({ hints: { email_proof: Number.NaN } })],
		["a hint that is an object", answer({ hints: { email_proof: { masked: true } as never } })],
		["hints that are not an object", answer({ hints: ["totp"] as never })],
	])("refuses %s with a RangeError", async (_label, body) => {
		const admission = await interrupt(async () => body as InterruptionAnswer);
		await expect(admission.open("express-1")).rejects.toThrow(RangeError);
	});

	it("admits every value shape a hint may take: a boolean, a finite number, an enum-like token, a list of tokens", async () => {
		const admission = await interrupt(
			async () => answer({ hints: { a: true, b: 3, c: "totp_or-email", d: ["x", "y"] } }),
			["a", "b", "c", "d"],
		);
		expect((await admission.open("express-1")).body.hints).toEqual({
			a: true,
			b: 3,
			c: "totp_or-email",
			d: ["x", "y"],
		});
	});

	it("holds a declared key to the grammar too: a reserved name, or one that is not an identifier, cannot be declared", () => {
		for (const key of ["user", "email", "Enrollable", "1st", "x".repeat(33), "a-b"]) {
			expect(
				() => resolverForTests([asking("r", () => "establish", { hintKeys: [key] })]),
				key,
			).toThrow(RangeError);
		}
	});
});

describe("resumePrimary — after a ceremony completes", () => {
	const continuation = (over: Partial<PrimaryContinuation> = {}): PrimaryContinuation => ({
		...continuationOf(primary(), [], "verifier"),
		...over,
	});

	it("records who interrupted in the continuation, and resumes only by that requirement's completion", async () => {
		const verifier = asking("verifier", () => interrupting());
		const risk = asking("risk", () => "establish");
		const first = await admitPrimary(deps([verifier, risk]), passwordPrimary(facts()));
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		expect(first.continuation.interruptedBy).toBe("verifier");
		await expect(
			resumePrimary(deps([verifier, risk]), first.continuation, {
				requirement: "risk",
				adds: { amr: ["risk-ok"] },
			}),
		).rejects.toThrow(RangeError);
		for (const interruptedBy of [undefined, "", 7, "other"]) {
			await expect(
				resumePrimary(deps([verifier, risk]), { ...first.continuation, interruptedBy } as never, {
					requirement: "verifier",
					adds: { amr: ["otp", "mfa"], mfaAt: NOW },
				}),
				JSON.stringify(interruptedBy),
			).rejects.toThrow(RangeError);
		}
	});

	it("recomposes recorded from the primary's kind — a password login, the only one interrupted in this release — never from the persisted DTO, and refuses any other kind", async () => {
		const verifier = asking("verifier", () => "establish");
		const tampered = {
			...continuation(),
			primary: {
				...continuation().primary,
				recorded: {
					amr: ["pwd", "kba"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				},
			},
		};
		const admission = await resumePrimary(deps([verifier]), tampered, {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		expect(admission.outcome).toBe("establish");
		if (admission.outcome !== "establish") throw new Error("unreachable");
		expect(admission.establishment.primary.recorded.amr).toEqual(["pwd", "otp", "mfa"]);
		const federated = {
			...continuation(),
			primary: {
				...continuation().primary,
				recorded: {
					amr: ["fed"],
					authentication: {
						primary: "fed",
						federation: "google",
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				},
			},
		};
		await expect(
			resumePrimary(deps([verifier]), federated, {
				requirement: "verifier",
				adds: { amr: ["otp", "mfa"], mfaAt: NOW },
			}),
		).rejects.toThrow(RangeError);
	});

	it("composes the session's recorded from the primary and every completed requirement's additions, and asks every requirement not yet done over it", async () => {
		const verifier = asking("verifier", (p) =>
			p.recorded.authentication.mfaAt === undefined ? interrupting() : "establish",
		);
		const risk = asking("risk", () => "establish");
		const admission = await resumePrimary(deps([verifier, risk]), continuation(), {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		expect(admission.outcome).toBe("establish");
		if (admission.outcome !== "establish") throw new Error("unreachable");
		expect(admission.establishment.primary.recorded).toEqual({
			amr: ["pwd", "otp", "mfa"],
			authentication: { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt: NOW },
		});
		expect(isEstablishment(admission.establishment)).toBe(true);
		// The completed one is done for this login and is not asked again; the
		// other is asked over the composed result.
		expect(verifier.asked).toEqual([]);
		expect(risk.asked.map((p) => p.recorded.authentication.mfaAt)).toEqual([NOW]);
	});

	it("asks a requirement that would interrupt every time once per login: its completion establishes, whatever it added", async () => {
		const always = asking("always", () => interrupting());
		const all = deps([always]);
		const first = await admitPrimary(all, passwordPrimary(facts()));
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		const resumed = await resumePrimary(all, first.continuation, {
			requirement: "always",
			adds: { amr: [] },
		});
		expect(resumed.outcome).toBe("establish");
		expect(always.asked).toHaveLength(1);
	});

	it("still asks a second requirement after the first completes, and neither again once both are done", async () => {
		const first = asking("first", () => interrupting());
		const second = asking("second", () => interrupting());
		const all = deps([first, second]);
		const atLogin = await admitPrimary(all, passwordPrimary(facts()));
		if (atLogin.outcome !== "interrupt") throw new Error("expected an interruption");
		expect(atLogin.requirement).toBe("first");
		// The login stops at the first interruption: the second is not asked yet.
		expect(second.asked).toHaveLength(0);
		const afterFirst = await resumePrimary(all, atLogin.continuation, {
			requirement: "first",
			adds: { amr: [] },
		});
		if (afterFirst.outcome !== "interrupt") throw new Error("expected the second to interrupt");
		expect(afterFirst.requirement).toBe("second");
		expect(afterFirst.continuation.done).toEqual([{ requirement: "first", adds: { amr: [] } }]);
		const afterSecond = await resumePrimary(all, afterFirst.continuation, {
			requirement: "second",
			adds: { amr: [] },
		});
		expect(afterSecond.outcome).toBe("establish");
		expect(first.asked).toHaveLength(1);
		expect(second.asked).toHaveLength(1);
	});

	it("interrupts again with the updated continuation, the first completion's additions still in it", async () => {
		const verifier = asking("verifier", (p) =>
			p.recorded.authentication.mfaAt === undefined ? interrupting() : "establish",
		);
		const risk = asking("risk", (p) =>
			p.recorded.amr.includes("risk-ok") ? "establish" : interrupting(),
		);
		const first = await resumePrimary(deps([verifier, risk]), continuation(), {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		expect(first).toMatchObject({
			outcome: "interrupt",
			requirement: "risk",
			continuation: continuationOf(
				primary(),
				[{ requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } }],
				"risk",
			),
		});
		if (first.outcome !== "interrupt") throw new Error("unreachable");
		// A persisted continuation is plain data: a JSON round trip resumes it,
		// the claims with it.
		const persisted = JSON.parse(JSON.stringify(first.continuation)) as PrimaryContinuation;
		expect(persisted.primary.claims).toEqual(facts().claims);
		const second = await resumePrimary(deps([verifier, risk]), persisted, {
			requirement: "risk",
			adds: { amr: ["risk-ok"] },
		});
		expect(second.outcome).toBe("establish");
		if (second.outcome !== "establish") throw new Error("unreachable");
		expect(second.establishment.primary.claims).toEqual(facts().claims);
		expect(second.establishment.primary.recorded).toEqual({
			amr: ["pwd", "otp", "mfa", "risk-ok"],
			authentication: { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt: NOW },
		});
	});

	it("refuses, before asking anything, a completion by a requirement that is not registered with admitPrimary, a continuation it cannot read, and what the name may not add", async () => {
		const verifier = asking("verifier", () => "establish");
		const plain: SessionRequirement = {
			name: "plain",
			reach: new Set(),
			stepUpPage: undefined,
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
		};
		const risk = asking("risk", () => "establish");
		const all = deps([verifier, plain, risk]);
		const cases: [
			string,
			PrimaryContinuation,
			{ requirement: string; adds: { amr: string[]; mfaAt?: Date } },
		][] = [
			["an unregistered name", continuation(), { requirement: "other", adds: { amr: ["x"] } }],
			[
				"a requirement without admitPrimary",
				continuation(),
				{ requirement: "plain", adds: { amr: ["x"] } },
			],
			[
				"a reserved value under another name",
				continuation(),
				{ requirement: "risk", adds: { amr: ["otp"] } },
			],
			[
				"an mfaAt under another name",
				continuation(),
				{ requirement: "risk", adds: { amr: ["risk-ok"], mfaAt: NOW } },
			],
			["a primary's marker", continuation(), { requirement: "verifier", adds: { amr: ["pwd"] } }],
			["mfa alone", continuation(), { requirement: "verifier", adds: { amr: ["mfa"] } }],
			[
				"a value outside the completing requirement's reach",
				continuation(),
				{ requirement: "risk", adds: { amr: ["risk-other"] } },
			],
			[
				"a second-factor value the authority's reach does not name",
				continuation(),
				{ requirement: "verifier", adds: { amr: ["swk", "mfa"], mfaAt: NOW } },
			],
			[
				"an earlier completion, read back, outside its requirement's reach",
				continuationOf(
					primary(),
					[{ requirement: "risk", adds: { amr: ["risk-other"] } }],
					"verifier",
				),
				{ requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
			],
			[
				"a name completing twice",
				continuationOf(
					primary(),
					[{ requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } }],
					"verifier",
				),
				{ requirement: "verifier", adds: { amr: ["hwk", "mfa"], mfaAt: NOW } },
			],
			[
				"a continuation carrying a date where milliseconds belong",
				{ primary: primary(), done: [] } as never,
				{ requirement: "verifier", adds: { amr: ["otp", "mfa"] } },
			],
			[
				"a continuation without a primary",
				{ done: [] } as never,
				{ requirement: "verifier", adds: { amr: ["otp", "mfa"] } },
			],
		];
		for (const [label, cont, completed] of cases) {
			await expect(resumePrimary(all, cont, completed), label).rejects.toThrow(RangeError);
		}
		await expect(
			resumePrimary({ ...all, requirements: {} as never }, continuation(), {
				requirement: "verifier",
				adds: { amr: ["otp", "mfa"] },
			}),
		).rejects.toThrow(RangeError);
		expect(verifier.asked).toEqual([]);
		expect(risk.asked).toEqual([]);
	});

	it("hands the next ceremony the updated continuation, the first completion in it", async () => {
		const verifier = asking("verifier", () => "establish");
		let received: unknown;
		const risk = asking("risk", (p) =>
			p.recorded.amr.includes("risk-ok")
				? "establish"
				: interrupting(async (_sessionId, continuation) => {
						received = continuation;
						return answer();
					}),
		);
		const second = await resumePrimary(deps([verifier, risk]), continuation(), {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		if (second.outcome !== "interrupt") throw new Error("expected an interruption");
		await second.open("express-2");
		expect(received).toBe(second.continuation);
		expect(received).toEqual(
			continuationOf(
				primary(),
				[{ requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } }],
				"risk",
			),
		);
	});

	it("refuses, before asking anything, a completion by the second-factor authority that is not a verified second factor — nothing added, no mfaAt, no mfa beside a factor that adds it — presented or read back from done", async () => {
		const verifier = asking("verifier", () => interrupting());
		const risk = asking("risk", () => interrupting());
		const all = deps([verifier, risk]);
		for (const adds of [{ amr: [] }, { amr: ["otp", "mfa"] }, { amr: ["otp"], mfaAt: NOW }]) {
			await expect(
				resumePrimary(all, continuation(), { requirement: "verifier", adds }),
				JSON.stringify(adds),
			).rejects.toThrow(RangeError);
			await expect(
				resumePrimary(all, continuationOf(primary(), [{ requirement: "verifier", adds }], "risk"), {
					requirement: "risk",
					adds: { amr: ["risk-ok"] },
				}),
				`done: ${JSON.stringify(adds)}`,
			).rejects.toThrow(RangeError);
		}
		expect(verifier.asked).toEqual([]);
		expect(risk.asked).toEqual([]);
		const verified = await resumePrimary(all, continuation(), {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		expect(verified.outcome).toBe("interrupt");
		expect(risk.asked).toHaveLength(1);
	});

	it("holds a requirement named mfa that does not declare the second-factor authority to what any other may add: a verified second factor is refused, presented or read back, even with a reach that names it", async () => {
		// The reach rules are lifted here, so only the missing declaration sets
		// it apart from the authority.
		const named = asking("mfa", () => interrupting(), {
			reach: new Set(["otp", "mfa"]),
			stepUpPage: { url: "/mfa", params: {} },
		});
		const risk = asking("risk", () => interrupting());
		const all = deps([named, risk]);
		const verified = { amr: ["otp", "mfa"], mfaAt: NOW };
		await expect(
			resumePrimary(all, continuationOf(primary(), [], "mfa"), {
				requirement: "mfa",
				adds: verified,
			}),
		).rejects.toThrow(/only the second-factor authority may add/);
		await expect(
			resumePrimary(
				all,
				continuationOf(primary(), [{ requirement: "mfa", adds: verified }], "risk"),
				{
					requirement: "risk",
					adds: { amr: ["risk-ok"] },
				},
			),
		).rejects.toThrow(/only the second-factor authority may add/);
		expect(named.asked).toEqual([]);
		expect(risk.asked).toEqual([]);
		// What it may add, it completes with.
		expect(
			(
				await resumePrimary(all, continuationOf(primary(), [], "mfa"), {
					requirement: "mfa",
					adds: { amr: [] },
				})
			).outcome,
		).toBe("interrupt");
	});

	it("composes the mfaAt the second-factor authority verified at, under a name that is not mfa", async () => {
		const verifier = asking("verifier", () => "establish");
		const admission = await resumePrimary(deps([verifier]), continuation(), {
			requirement: "verifier",
			adds: { amr: ["hwk", "mfa"], mfaAt: NOW },
		});
		if (admission.outcome !== "establish") throw new Error("expected an establishment");
		expect(admission.establishment.primary.recorded).toEqual({
			amr: ["pwd", "hwk", "mfa"],
			authentication: { primary: "pwd", federation: undefined, upstreamAmr: undefined, mfaAt: NOW },
		});
	});

	it("refuses deps that are not an object, a completion without a requirement's name, and a done entry naming a requirement that is not registered", async () => {
		const verifier = asking("verifier", () => "establish");
		await expect(admitPrimary("deps" as never, passwordPrimary(facts()))).rejects.toThrow(
			/admitPrimary: deps must be an object/,
		);
		await expect(
			resumePrimary("deps" as never, continuation(), {
				requirement: "verifier",
				adds: { amr: [] },
			}),
		).rejects.toThrow(/resumePrimary: deps must be an object/);
		for (const completed of [null, "mfa", { requirement: "" }, { adds: { amr: [] } }]) {
			await expect(
				resumePrimary(deps([verifier]), continuation(), completed as never),
				JSON.stringify(completed),
			).rejects.toThrow(/the completion must name a requirement/);
		}
		await expect(
			resumePrimary(
				deps([verifier]),
				continuationOf(primary(), [{ requirement: "gone", adds: { amr: [] } }], "verifier"),
				{ requirement: "verifier", adds: { amr: ["otp", "mfa"], mfaAt: NOW } },
			),
		).rejects.toThrow(/"gone" is not a registered requirement that interrupts a login/);
		expect(verifier.asked).toEqual([]);
	});

	it("answers unavailable when a requirement throws on the second ask", async () => {
		const verifier = asking("verifier", () => "establish");
		const risk = asking("risk", () => {
			throw new Error("down");
		});
		expect(
			await resumePrimary(deps([verifier, risk]), continuation(), {
				requirement: "verifier",
				adds: { amr: ["otp", "mfa"], mfaAt: NOW },
			}),
		).toEqual({ outcome: "unavailable", store: "risk" });
	});
});

describe("establishWithoutAsking — a federated login's establishment, from the federation's own facts", () => {
	const federated = {
		subject: "user-1",
		user: { id: "user-1" },
		claims: { email: "user-1@example.test", name: "User One" },
		federation: "google",
		upstreamAmr: ["mfa", "hwk"],
		trusted: false,
		authTime: NOW,
		redirectTo: "/after",
		request: { ip: "198.51.100.7" },
	};

	it("composes recorded through federatedSessionAuthentication: an untrusted IdP's values kept apart", () => {
		const establishment = establishWithoutAsking(federated);
		expect(isEstablishment(establishment)).toBe(true);
		expect(establishment.primary).toEqual({
			subject: "user-1",
			user: { id: "user-1" },
			claims: { email: "user-1@example.test", name: "User One" },
			recorded: {
				amr: ["fed"],
				authentication: {
					primary: "fed",
					federation: "google",
					upstreamAmr: ["mfa", "hwk"],
					mfaAt: undefined,
				},
			},
			enrollmentFacts: { witness: "not_enrolled", mailAddress: "none" },
			authTime: NOW,
			redirectTo: "/after",
			request: { ip: "198.51.100.7" },
		});
	});

	it("records a trusted IdP's values beside fed", () => {
		const establishment = establishWithoutAsking({ ...federated, trusted: true });
		expect(establishment.primary.recorded).toEqual({
			amr: ["mfa", "hwk", "fed"],
			authentication: {
				primary: "fed",
				federation: "google",
				upstreamAmr: undefined,
				mfaAt: undefined,
			},
		});
	});

	it("takes no primary: an amr, an mfaAt or a recorded handed in is not a federation's fact", () => {
		for (const bad of [
			{ ...federated, federation: "" },
			{ ...federated, upstreamAmr: "mfa" },
			{ ...federated, upstreamAmr: [7] },
			{ ...federated, trusted: "yes" },
			{ ...federated, subject: "" },
			{ ...federated, authTime: "now" },
			{ ...federated, user: undefined },
			{ ...federated, request: undefined },
			undefined,
		]) {
			expect(() => establishWithoutAsking(bad as never), JSON.stringify(bad)).toThrow(RangeError);
		}
	});
});

describe("isEstablishment — the capability to establish", () => {
	it("knows only what admitPrimary, resumePrimary and establishWithoutAsking built: a copy forges nothing", async () => {
		const admission = await admitPrimary(deps([]), passwordPrimary(facts()));
		if (admission.outcome !== "establish") throw new Error("unreachable");
		expect(isEstablishment(admission.establishment)).toBe(true);
		expect(isEstablishment({ ...admission.establishment })).toBe(false);
		expect(isEstablishment({ primary: primary() })).toBe(false);
		expect(isEstablishment(undefined)).toBe(false);
		expect(isEstablishment(null)).toBe(false);
	});
});

describe("isInterruptAdmission — an interruption is core's, as an establishment is", () => {
	it("knows only the interruptions admitPrimary and resumePrimary answered: a copy, or an object shaped like one, forges nothing", async () => {
		const verifier = asking("verifier", () => interrupting());
		const risk = asking("risk", () => interrupting());
		const all = deps([verifier, risk]);
		const atLogin = await admitPrimary(all, passwordPrimary(facts()));
		if (atLogin.outcome !== "interrupt") throw new Error("expected an interruption");
		expect(isInterruptAdmission(atLogin)).toBe(true);
		const resumed = await resumePrimary(all, atLogin.continuation, {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		if (resumed.outcome !== "interrupt") throw new Error("expected the second to interrupt");
		expect(isInterruptAdmission(resumed)).toBe(true);
		expect(Object.isFrozen(resumed)).toBe(true);
		expect(isInterruptAdmission({ ...atLogin })).toBe(false);
		expect(
			isInterruptAdmission({
				outcome: "interrupt",
				requirement: "verifier",
				continuation: atLogin.continuation,
				open: atLogin.open,
			}),
		).toBe(false);
		const established = await admitPrimary(deps([]), passwordPrimary(facts()));
		expect(isInterruptAdmission(established)).toBe(false);
		expect(isInterruptAdmission(undefined)).toBe(false);
		expect(isInterruptAdmission(null)).toBe(false);
	});
});
