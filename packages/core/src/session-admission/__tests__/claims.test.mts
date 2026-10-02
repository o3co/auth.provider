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
 * The claims envelope a login records — what the session record's `claims`
 * will hold — read as core's builders read the `User`: each claim
 * `UserSessionClaims` declares by name, once, however the object holds it,
 * and each custom claim by its own key, copied as plain data. So the
 * envelope a route seeds from an ORM-backed `User` — its `groups` an ORM's
 * list, a Proxy or an Array subclass — logs in, and what is stored is a
 * plain string array with nothing else of the list.
 */

import { describe, expect, it } from "vitest";
import type { Logger } from "#/logging/Logger.mjs";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitPrimary,
	establishWithoutAsking,
	passwordPrimary,
	resumePrimary,
} from "#/session-admission/admit.mjs";
import { checkPrimaryContinuation } from "#/session-admission/primary.mjs";
import type { AdmissionDeps, SessionRequirement } from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";

const NOW = new Date("2026-10-02T12:00:00Z");

/** The claims a route seeds from `user`, as the session package's `extractUserClaims` does: `user.groups` itself, not a copy. */
const seededClaims = (user: Record<string, unknown>): Record<string, unknown> => {
	const claims: Record<string, unknown> = {};
	if (typeof user.email === "string") claims.email = user.email;
	if (Array.isArray(user.groups)) claims.groups = user.groups;
	return claims;
};

const passwordFacts = (claims: unknown) => ({
	subject: "user-1",
	user: { id: "user-1" },
	claims,
	authTime: NOW,
	redirectTo: undefined,
	request: {},
});

const federatedLogin = (claims: unknown) => ({
	subject: "user-1",
	user: { id: "user-1" },
	claims,
	federation: "google",
	upstreamAmr: [],
	trusted: false,
	authTime: NOW,
	redirectTo: undefined,
	request: {},
});

/** Both builders over `claims`: the claims of the password login's primary and of the federated login's. */
const bothLogins = (claims: unknown) => [
	() => passwordPrimary(passwordFacts(claims) as never).claims,
	() => establishWithoutAsking(federatedLogin(claims) as never).primary.claims,
];

/** A list as an ORM hands one out: an array of its own list type behind a Proxy, as Mongoose's arrays are. */
function proxiedList(values: readonly string[]): string[] {
	class OrmArray<T> extends Array<T> {}
	const list = OrmArray.from(values);
	return new Proxy(list, {
		get(target, key, receiver) {
			return Reflect.get(target, key, receiver);
		},
	});
}

/** An entity as an ORM hands it out: its columns in an internal record, each a getter on the prototype. */
function ormEntity(columns: Record<string, unknown>): Record<string, unknown> {
	class Entity {
		dataValues: Record<string, unknown>;
		constructor(values: Record<string, unknown>) {
			this.dataValues = values;
		}
	}
	for (const column of Object.keys(columns)) {
		Object.defineProperty(Entity.prototype, column, {
			get(this: Entity) {
				return this.dataValues[column];
			},
			configurable: true,
		});
	}
	return new Entity({ ...columns }) as unknown as Record<string, unknown>;
}

describe("a login whose User's groups is an ORM's list logs in, its claims' groups a plain string array", () => {
	it("takes a Proxy-backed list, which structuredClone cannot copy, on both logins", () => {
		const groups = proxiedList(["staff", "admin"]);
		expect(() => structuredClone(groups)).toThrow();
		const user = ormEntity({ id: "user-1", email: "alice@example.com", groups });
		for (const build of bothLogins(seededClaims(user))) {
			const claims = build();
			expect(claims).toStrictEqual({ email: "alice@example.com", groups: ["staff", "admin"] });
			expect(claims.groups).not.toBe(groups);
			expect(Array.isArray(claims.groups)).toBe(true);
			expect(Reflect.getPrototypeOf(claims.groups as object)).toBe(Array.prototype);
			expect(Object.isFrozen(claims)).toBe(true);
			expect(Object.isFrozen(claims.groups)).toBe(true);
			expect(JSON.parse(JSON.stringify(claims))).toStrictEqual(claims);
		}
	});

	it("copies a Proxy-backed list in index order, whatever order the Proxy lists its keys in", () => {
		const groups = new Proxy(["staff", "admin"], {
			ownKeys: (target) => Reflect.ownKeys(target).reverse(),
		});
		for (const build of bothLogins(seededClaims({ groups }))) {
			expect(build().groups).toStrictEqual(["staff", "admin"]);
		}
	});

	it("takes an Array subclass carrying own enumerable properties of its own, and copies its elements alone", () => {
		class TrackedArray<T> extends Array<T> {}
		const groups = Object.assign(TrackedArray.from(["staff", "admin"]), {
			_parent: "user-1",
			_atomics: { $push: ["admin"] },
		});
		for (const build of bothLogins(seededClaims({ groups }))) {
			const claims = build();
			expect(claims).toStrictEqual({ groups: ["staff", "admin"] });
			expect(Object.keys(claims.groups as object)).toEqual(["0", "1"]);
			expect(Reflect.getPrototypeOf(claims.groups as object)).toBe(Array.prototype);
		}
	});

	it("records them through an interruption: the continuation round-trips as JSON and the resumed login holds them", async () => {
		const verifier: SessionRequirement = {
			name: "verifier",
			secondFactorAuthority: true,
			reach: new Set(["otp", "mfa"]),
			stepUpPage: { url: "/verifier", params: {} },
			remediations: [],
			hintKeys: [],
			admit: async () => ({ outcome: "met" }),
			admitPrimary: async (primary) =>
				primary.recorded.authentication.mfaAt === undefined
					? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
					: "establish",
		};
		const deps: AdmissionDeps = {
			userSessionStore: undefined,
			subjectRevocation: undefined,
			requirements: resolverForTests([verifier], { issuer: "https://auth.test" }),
			acrTable: readAcrTable({}),
			logger: undefined,
			auditSink: undefined,
			now: () => NOW,
		};
		const user = ormEntity({ id: "user-1", groups: proxiedList(["staff"]) });
		const first = await admitPrimary(
			deps,
			passwordPrimary(passwordFacts(seededClaims(user)) as never),
		);
		if (first.outcome !== "interrupt") throw new Error("expected an interruption");
		const stored = JSON.parse(JSON.stringify(first.continuation));
		expect(checkPrimaryContinuation(stored).primary.claims).toStrictEqual({ groups: ["staff"] });
		const resumed = await resumePrimary(deps, stored, {
			requirement: "verifier",
			adds: { amr: ["otp", "mfa"], mfaAt: NOW },
		});
		if (resumed.outcome !== "establish") throw new Error("expected an establishment");
		expect(resumed.establishment.primary.claims).toStrictEqual({ groups: ["staff"] });
	});
});

describe("the claims are read by name, each once, into a plain copy", () => {
	it("reads each declared claim and each custom claim once, and nothing of them after the build", () => {
		// Each read counted by the object it is made of and the key it names.
		const reads = new Map<string, number>();
		const counting = <T extends object>(label: string, target: T): T =>
			new Proxy(target, {
				get(of, key, receiver) {
					if (typeof key === "string") {
						const read = `${label}.${key}`;
						reads.set(read, (reads.get(read) ?? 0) + 1);
					}
					return Reflect.get(of, key, receiver);
				},
			});
		const source = {
			email: "alice@example.com",
			emailVerified: true,
			name: "Alice",
			picture: "https://example.com/alice.png",
			groups: counting("groups", ["staff", "admin"]),
			federated: counting("federated", {
				google: counting("google", { hd: "example.com" }),
			}),
			tenant: "acme",
		};
		for (const build of bothLogins(counting("claims", source))) {
			reads.clear();
			const claims = build();
			for (const key of [
				"email",
				"emailVerified",
				"name",
				"picture",
				"groups",
				"federated",
				"tenant",
			]) {
				expect(reads.get(`claims.${key}`)).toBe(1);
			}
			// Each of the list's elements, by index, and each key of the custom claim, once.
			expect(reads.get("groups.0")).toBe(1);
			expect(reads.get("groups.1")).toBe(1);
			expect(reads.get("federated.google")).toBe(1);
			expect(reads.get("google.hd")).toBe(1);
			expect([...reads.values()].every((count) => count === 1)).toBe(true);
			reads.clear();
			expect(claims).toStrictEqual({
				email: "alice@example.com",
				emailVerified: true,
				name: "Alice",
				picture: "https://example.com/alice.png",
				groups: ["staff", "admin"],
				federated: { google: { hd: "example.com" } },
				tenant: "acme",
			});
			expect(reads.size).toBe(0);
		}
	});

	it("reads a declared claim however the object holds it — a prototype getter included — and a custom claim by its own key", () => {
		const claims = new (class {
			tenant = "acme";
			get email() {
				return "alice@example.com";
			}
			get groups() {
				return proxiedList(["staff"]);
			}
		})();
		for (const build of bothLogins(claims)) {
			expect(build()).toStrictEqual({
				email: "alice@example.com",
				groups: ["staff"],
				tenant: "acme",
			});
		}
	});

	it("copies a custom claim's plain data at any depth, frozen and shared with nothing", () => {
		let deep: Record<string, unknown> = { leaf: [1, "two", null, false] };
		for (let level = 0; level < 50; level += 1) deep = { next: deep };
		const source = { custom: { nested: [{ roles: ["staff"] }] }, deep };
		for (const build of bothLogins(source)) {
			const claims = build() as { custom: { nested: [{ roles: string[] }] } };
			expect(claims).toStrictEqual(source);
			expect(claims.custom).not.toBe(source.custom);
			expect(Object.isFrozen(claims.custom.nested[0].roles)).toBe(true);
		}
	});

	it("reads a null-prototype claims object as any other", () => {
		const claims = Object.assign(Object.create(null), {
			email: "alice@example.com",
			groups: proxiedList(["staff"]),
			custom: { tier: "gold" },
		});
		for (const build of bothLogins(claims)) {
			expect(build()).toStrictEqual({
				email: "alice@example.com",
				groups: ["staff"],
				custom: { tier: "gold" },
			});
		}
	});

	it("reads a frozen claims object, and answers a copy that is not it", () => {
		const claims = Object.freeze({
			email: "alice@example.com",
			groups: Object.freeze(["staff"]),
			custom: Object.freeze({ tier: "gold" }),
		});
		for (const build of bothLogins(claims)) {
			const copied = build();
			expect(copied).toStrictEqual(claims);
			expect(copied).not.toBe(claims);
			expect(copied.groups).not.toBe(claims.groups);
		}
	});

	it("lets a getter that throws through as it threw", () => {
		const outage = new Error("the entity's connection is closed");
		const claims = Object.defineProperty({}, "groups", {
			get() {
				throw outage;
			},
		});
		for (const build of bothLogins(claims)) {
			let thrown: unknown;
			try {
				build();
			} catch (err) {
				thrown = err;
			}
			expect(thrown).toBe(outage);
		}
	});
});

describe("malformed claims are refused", () => {
	it.each([
		["claims that are not an object", "email", /claims must be an object/],
		["claims that are a list", ["email"], /claims must be an object/],
		["groups that is not a list", { groups: "staff" }, /claims\.groups must be a list of strings/],
		[
			"groups that holds what is not a string",
			{ groups: ["staff", 7] },
			/claims\.groups must be a list of strings/,
		],
		[
			"an ORM's list that holds what is not a string",
			{ groups: new Proxy(["staff", { id: 7 }], {}) },
			/claims\.groups must be a list of strings/,
		],
		["an email that is not a string", { email: 7 }, /claims\.email must be a string/],
		[
			"an emailVerified that is not a boolean",
			{ emailVerified: "true" },
			/claims\.emailVerified must be a boolean/,
		],
		["a name that is not a string", { name: null }, /claims\.name must be a string/],
		["an email that is null", { email: null }, /claims\.email must be a string/],
		["a picture that is not a string", { picture: ["x"] }, /claims\.picture must be a string/],
		["an email that is a Date", { email: new Date(0) }, /claims\.email must be a string/],
		["a name that is a function", { name: () => "Alice" }, /claims\.name must be a string/],
		[
			"an emailVerified that is a bigint",
			{ emailVerified: 1n },
			/claims\.emailVerified must be a boolean/,
		],
		[
			"groups that holds a list with a hole",
			// biome-ignore lint/suspicious/noSparseArray: the hole is the case
			{ groups: ["staff", , "admin"] },
			/claims\.groups must be a list of strings/,
		],
	] as const)("refuses %s with a RangeError, on both logins", (_label, claims, message) => {
		for (const build of bothLogins(claims)) {
			expect(build).toThrow(RangeError);
			expect(build).toThrow(message);
		}
	});
});

/** A logger that records each warn it is handed. */
const recordingLogger = () => {
	const warns: { readonly fields: Record<string, unknown>; readonly message: unknown }[] = [];
	const logger = {
		trace: () => {},
		debug: () => {},
		info: () => {},
		warn: (fields: Record<string, unknown>, message?: unknown) => {
			warns.push({ fields, message });
		},
		error: () => {},
		fatal: () => {},
		child: () => logger,
	} as unknown as Logger;
	return { logger, warns };
};

/** Admission over no requirement: a login is established as it is built. */
const depsWith = (logger: Logger | undefined): AdmissionDeps => ({
	userSessionStore: undefined,
	subjectRevocation: undefined,
	requirements: resolverForTests([], { issuer: "https://auth.test" }),
	acrTable: readAcrTable({}),
	logger,
	auditSink: undefined,
	now: () => NOW,
});

describe("a custom claim is stored as its JSON form", () => {
	it("stores a Date as its ISO string, an object with toJSON as what toJSON answers, and NaN or Infinity as null", () => {
		const id = { toJSON: () => "65f1c0ffee0000000000beef" };
		const source = {
			joined: new Date(0),
			id,
			nested: { at: new Date(1000), ids: [id], score: Number.NaN },
			ratio: Number.POSITIVE_INFINITY,
		};
		for (const build of bothLogins(source)) {
			const claims = build();
			expect(claims).toStrictEqual({
				joined: "1970-01-01T00:00:00.000Z",
				id: "65f1c0ffee0000000000beef",
				nested: {
					at: "1970-01-01T00:00:01.000Z",
					ids: ["65f1c0ffee0000000000beef"],
					score: null,
				},
				ratio: null,
			});
			expect(Object.isFrozen((claims as { nested: object }).nested)).toBe(true);
			expect(Object.isFrozen((claims as { nested: { ids: object } }).nested.ids)).toBe(true);
		}
	});

	it("leaves out, as JSON does and with no warn, a custom claim whose JSON form is nothing", async () => {
		const { logger, warns } = recordingLogger();
		const source = { hook: () => 1, gone: undefined, tag: Symbol("t"), kept: "yes" };
		const admission = await admitPrimary(
			depsWith(logger),
			passwordPrimary(passwordFacts(source) as never),
		);
		if (admission.outcome !== "establish") throw new Error("expected an establishment");
		expect(admission.establishment.primary.claims).toStrictEqual({ kept: "yes" });
		expect(warns).toEqual([]);
	});

	it("takes a custom claim nested deeper than a thousand levels", () => {
		let deep: Record<string, unknown> = { leaf: true };
		for (let level = 0; level < 1100; level += 1) deep = { next: deep };
		for (const build of bothLogins({ deep })) {
			expect(build()).toStrictEqual({ deep });
		}
	});

	describe("drops a custom claim whose JSON form cannot be taken, warning once for each and never quoting it, and the login goes on", () => {
		const cyclic: Record<string, unknown> = { secret: "do-not-log" };
		cyclic.self = cyclic;
		const outage = new Error("the entity's connection is closed");
		const source = () => ({
			email: "alice@example.com",
			big: 12345678901234567890n,
			loop: cyclic,
			broken: {
				toJSON() {
					throw outage;
				},
			},
			kept: { tier: "gold" },
		});
		const dropped = [
			{ claim: "big", reason: "unserialisable" },
			{ claim: "loop", reason: "unserialisable" },
			{ claim: "broken", reason: "unserialisable" },
		];
		const expectWarned = (warns: ReturnType<typeof recordingLogger>["warns"]) => {
			expect(warns.map((line) => line.fields)).toStrictEqual(dropped);
			expect(warns.every((line) => line.message === "login_claim_dropped")).toBe(true);
			expect(JSON.stringify(warns)).not.toContain("do-not-log");
		};

		it("on the password login, through admitPrimary's logger", async () => {
			const { logger, warns } = recordingLogger();
			const admission = await admitPrimary(
				depsWith(logger),
				passwordPrimary(passwordFacts(source()) as never),
			);
			if (admission.outcome !== "establish") throw new Error("expected an establishment");
			expect(admission.establishment.primary.claims).toStrictEqual({
				email: "alice@example.com",
				kept: { tier: "gold" },
			});
			expectWarned(warns);
		});

		it("on the federated login, through the logger it is handed", () => {
			const { logger, warns } = recordingLogger();
			const establishment = establishWithoutAsking(federatedLogin(source()) as never, { logger });
			expect(establishment.primary.claims).toStrictEqual({
				email: "alice@example.com",
				kept: { tier: "gold" },
			});
			expectWarned(warns);
		});

		it("on the federated login without a logger, silently", () => {
			const establishment = establishWithoutAsking(federatedLogin(source()) as never);
			expect(establishment.primary.claims).toStrictEqual({
				email: "alice@example.com",
				kept: { tier: "gold" },
			});
		});

		it("on a resumed login, through resumePrimary's logger", async () => {
			const verifier: SessionRequirement = {
				name: "verifier",
				secondFactorAuthority: true,
				reach: new Set(["otp", "mfa"]),
				stepUpPage: { url: "/verifier", params: {} },
				remediations: [],
				hintKeys: [],
				admit: async () => ({ outcome: "met" }),
				admitPrimary: async (primary) =>
					primary.recorded.authentication.mfaAt === undefined
						? { open: async () => ({ status: 403, body: { error: "mfa_required" } }) }
						: "establish",
			};
			const { logger, warns } = recordingLogger();
			const deps = {
				...depsWith(logger),
				requirements: resolverForTests([verifier], { issuer: "https://auth.test" }),
			};
			const first = await admitPrimary(deps, passwordPrimary(passwordFacts({}) as never));
			if (first.outcome !== "interrupt") throw new Error("expected an interruption");
			// A continuation a store answered with what JSON cannot hold.
			const handedBack = {
				...first.continuation,
				primary: { ...first.continuation.primary, claims: source() },
			};
			const resumed = await resumePrimary(deps, handedBack, {
				requirement: "verifier",
				adds: { amr: ["otp", "mfa"], mfaAt: NOW },
			});
			if (resumed.outcome !== "establish") throw new Error("expected an establishment");
			expect(resumed.establishment.primary.claims).toStrictEqual({
				email: "alice@example.com",
				kept: { tier: "gold" },
			});
			expectWarned(warns);
		});
	});

	it("stores a number JSON cannot hold as null, even one a toJSON spells out raw", () => {
		const raw = (JSON as unknown as { rawJSON: (text: string) => unknown }).rawJSON;
		const source = { huge: { toJSON: () => raw("1e400") }, list: [raw("-1e400"), 1] };
		for (const build of bothLogins(source)) {
			expect(build()).toStrictEqual({ huge: null, list: [null, 1] });
		}
	});

	it("drops a custom claim that refers back to the claims, reading nothing of them again", async () => {
		const reads = new Map<string, number>();
		const target: Record<string, unknown> = {};
		Object.defineProperty(target, "email", {
			get() {
				reads.set("email", (reads.get("email") ?? 0) + 1);
				return "alice@example.com";
			},
			enumerable: true,
		});
		target.owner = { of: target };
		const { logger, warns } = recordingLogger();
		const admission = await admitPrimary(
			depsWith(logger),
			passwordPrimary(passwordFacts(target) as never),
		);
		if (admission.outcome !== "establish") throw new Error("expected an establishment");
		expect(admission.establishment.primary.claims).toStrictEqual({ email: "alice@example.com" });
		expect(reads.get("email")).toBe(1);
		expect(warns.map((line) => line.fields)).toStrictEqual([
			{ claim: "owner", reason: "unserialisable" },
		]);
	});

	it("warns of a dropped claim once, however often its primary is admitted", async () => {
		const { logger, warns } = recordingLogger();
		const primary = passwordPrimary(passwordFacts({ big: 1n }) as never);
		await admitPrimary(depsWith(logger), primary);
		await admitPrimary(depsWith(logger), primary);
		expect(warns).toHaveLength(1);
	});

	it("still refuses a declared claim of the wrong type beside custom claims", () => {
		for (const build of bothLogins({ groups: "staff", joined: new Date(0) })) {
			expect(build).toThrow(/claims\.groups must be a list of strings/);
		}
	});
});
