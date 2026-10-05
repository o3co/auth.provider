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
 * Admission over a record bound to a renewed cookie session: a record that
 * carries a renewal nonce is live only for the cookie session holding the
 * same one — any other, an old express id a concurrent request saved back
 * included, is `not_live` (`renewed`). A record without one is read as
 * before; a token, code or link carrier is never compared.
 */

import { describe, expect, it } from "vitest";
import { readAcrTable } from "#/session-admission/acr.mjs";
import {
	admitSession,
	codeClaimRevalidation,
	cookieClaim,
	cookieRenewedAway,
	linkClaim,
	tokenClaim,
} from "#/session-admission/admit.mjs";
import type {
	AdmissionDeps,
	SessionClaim,
	SessionRequirement,
} from "#/session-admission/requirement.mjs";
import { resolverForTests } from "#/session-admission/testing/resolver.mjs";
import { createInMemoryUserSessionStore } from "#/user-sessions/memory/userSessionStore.mjs";
import { newRenewalNonce } from "#/user-sessions/renewalNonce.mjs";
import type { UserSessionStore } from "#/user-sessions/types.mjs";
import { TEST_ACTIONS } from "./actions.fixture.mjs";

const SID = "sid-1";
const SUB = "user-1";

/** A memory store holding one password session, escalated with `renewalNonce` when one is given. */
async function holding(renewalNonce?: string) {
	const store = createInMemoryUserSessionStore();
	const now = Date.now();
	await store.create({
		sid: SID,
		sub: SUB,
		authTime: new Date(now - 60_000),
		expiresAt: new Date(now + 3_600_000),
		claims: {},
		amr: ["pwd"],
		authentication: {
			primary: "pwd",
			federation: undefined,
			upstreamAmr: undefined,
			mfaAt: undefined,
		},
	});
	if (renewalNonce !== undefined) {
		await store.recordSecondFactor(SID, { amr: ["otp", "mfa"], at: new Date(now), renewalNonce });
	}
	return store;
}

const deps = (store: UserSessionStore): AdmissionDeps => ({
	userSessionStore: store,
	subjectRevocation: undefined,
	requirements: resolverForTests([], { actions: TEST_ACTIONS }),
	acrTable: readAcrTable({}),
	logger: undefined,
	auditSink: undefined,
});

/** The cookie a browser presents: signed in for `SUB` on `SID`, holding `renewalNonce` when given. */
const cookie = (renewalNonce?: unknown): SessionClaim =>
	cookieClaim({
		session: {
			isAuthenticated: true,
			sid: SID,
			user: { id: SUB },
			...(renewalNonce === undefined ? {} : { renewalNonce }),
		},
	});

const admit = async (store: UserSessionStore, claim: SessionClaim) =>
	admitSession(deps(store), { claim, action: "test.use" });

describe("admission over a session bound to a renewed cookie session", () => {
	it("reads the cookie session's renewal nonce into the cookie's claim, and nothing else's", () => {
		const nonce = newRenewalNonce();
		expect(cookie(nonce).renewalNonce).toBe(nonce);
		expect(cookie()).not.toHaveProperty("renewalNonce");
		expect(cookie("")).not.toHaveProperty("renewalNonce");
		expect(tokenClaim({ sid: SID, sub: SUB })).not.toHaveProperty("renewalNonce");
	});

	it("admits the cookie session holding the record's nonce", async () => {
		const nonce = newRenewalNonce();
		expect(await admit(await holding(nonce), cookie(nonce))).toMatchObject({
			outcome: "admitted",
		});
	});

	it("refuses, not_live (renewed), a cookie session holding another nonce or none: an old id saved back after the renewal", async () => {
		const store = await holding(newRenewalNonce());
		for (const presented of [undefined, newRenewalNonce(), "not-a-nonce"]) {
			expect(await admit(store, cookie(presented)), String(presented)).toEqual({
				outcome: "not_live",
				reason: "renewed",
			});
		}
	});

	it("reads a record without a nonce as before, whatever the cookie session holds", async () => {
		const store = await holding();
		for (const presented of [undefined, newRenewalNonce()]) {
			expect(await admit(store, cookie(presented)), String(presented)).toMatchObject({
				outcome: "admitted",
			});
		}
	});

	it("refuses a record whose nonce a store answers in another shape", async () => {
		const inner = await holding();
		const odd: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				return session === null ? null : { ...session, renewalNonce: 7 as unknown as string };
			},
		};
		expect(await admit(odd, cookie())).toEqual({ outcome: "not_live", reason: "renewed" });
	});

	it("refuses a record whose nonce is not one, even when the cookie session holds that very value", async () => {
		const inner = await holding();
		const malformed = "not-a-nonce";
		const odd: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				return session === null ? null : { ...session, renewalNonce: malformed };
			},
		};
		expect(await admit(odd, cookie(malformed))).toEqual({ outcome: "not_live", reason: "renewed" });
	});

	it("reads the record's nonce once: a getter that answers another value on a second read changes nothing", async () => {
		const inner = await holding();
		const presented = newRenewalNonce();
		for (const [first, later] of [
			["not-a-nonce", presented],
			[newRenewalNonce(), presented],
		] as const) {
			let reads = 0;
			const odd: UserSessionStore = {
				...inner,
				get: async (sid) => {
					const session = await inner.get(sid);
					if (session === null) return null;
					return Object.defineProperty({ ...session }, "renewalNonce", {
						enumerable: true,
						get: () => {
							reads++;
							return reads === 1 ? first : later;
						},
					});
				},
			};
			expect(await admit(odd, cookie(presented)), first).toEqual({
				outcome: "not_live",
				reason: "renewed",
			});
			expect(reads, first).toBe(1);
		}
	});

	it("never compares a token or a code carrier's claim: the nonce is the cookie session's", async () => {
		const store = await holding(newRenewalNonce());
		expect(await admit(store, tokenClaim({ sid: SID, sub: SUB }))).toMatchObject({
			outcome: "admitted",
		});
		expect(await admit(store, codeClaimRevalidation({ sid: SID }, SUB))).toMatchObject({
			outcome: "admitted",
		});
	});
});

describe("cookieRenewedAway — whether the record a cookie names is bound to another cookie session", () => {
	it("answers true for a cookie session that does not hold the record's nonce, false for the one that does", async () => {
		const nonce = newRenewalNonce();
		const store = await holding(nonce);
		expect(await cookieRenewedAway(store, cookie(nonce))).toBe(false);
		for (const presented of [undefined, newRenewalNonce()]) {
			expect(await cookieRenewedAway(store, cookie(presented)), String(presented)).toBe(true);
		}
	});

	it("answers false for a record without a nonce, a record that is gone, and a claim that is not a cookie's", async () => {
		expect(await cookieRenewedAway(await holding(), cookie(newRenewalNonce()))).toBe(false);
		expect(await cookieRenewedAway(createInMemoryUserSessionStore(), cookie())).toBe(false);
		expect(
			await cookieRenewedAway(await holding(newRenewalNonce()), tokenClaim({ sid: SID, sub: SUB })),
		).toBe(false);
	});

	it("reads the record's nonce once, refuses one that is not a nonce, and rejects with the store's outage", async () => {
		const inner = await holding();
		let reads = 0;
		const odd: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				if (session === null) return null;
				return Object.defineProperty({ ...session }, "renewalNonce", {
					enumerable: true,
					get: () => (reads++ === 0 ? "not-a-nonce" : undefined),
				});
			},
		};
		expect(await cookieRenewedAway(odd, cookie("not-a-nonce"))).toBe(true);
		expect(reads).toBe(1);
		const down: UserSessionStore = {
			...inner,
			get: async () => {
				throw new Error("store down");
			},
		};
		await expect(cookieRenewedAway(down, cookie())).rejects.toThrow("store down");
	});
});

/**
 * What a consumer that writes the record next expects of it: the record's own
 * renewal nonce as admission read it, so a conditional write compares with the
 * record and not with the cookie session.
 */
describe("the admitted outcome carries the record's renewal nonce", () => {
	it("carries the record's nonce, which the cookie session holding it presented", async () => {
		const nonce = newRenewalNonce();
		expect(await admit(await holding(nonce), cookie(nonce))).toMatchObject({
			outcome: "admitted",
			renewalNonce: nonce,
		});
	});

	it("carries none for a record without one, whatever the cookie session holds", async () => {
		const store = await holding();
		for (const presented of [undefined, newRenewalNonce()]) {
			const admission = await admit(store, cookie(presented));
			expect(admission, String(presented)).toMatchObject({ outcome: "admitted" });
			expect(Object.hasOwn(admission, "renewalNonce"), String(presented)).toBe(false);
		}
	});

	it("reads the record's nonce once: an accessor answering another value later changes nothing", async () => {
		const nonce = newRenewalNonce();
		const inner = await holding(nonce);
		const flipping: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				if (session === null) return null;
				let reads = 0;
				return Object.defineProperty({ ...session }, "renewalNonce", {
					get: () => (reads++ === 0 ? nonce : newRenewalNonce()),
					enumerable: true,
				});
			},
		};
		expect(await admit(flipping, cookie(nonce))).toMatchObject({
			outcome: "admitted",
			renewalNonce: nonce,
		});
	});

	/** A requirement that is always met, so admission asks it and reads the record again (step 8). */
	const asked: SessionRequirement = {
		name: "asked",
		reach: new Set(),
		stepUpPage: undefined,
		remediations: [],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
	};
	const withRequirement = (store: UserSessionStore): AdmissionDeps => ({
		...deps(store),
		requirements: resolverForTests([asked], { actions: TEST_ACTIONS }),
	});

	it("carries the first reading's nonce through the last reading, a requirement having been asked", async () => {
		const nonce = newRenewalNonce();
		expect(
			await admitSession(withRequirement(await holding(nonce)), {
				claim: cookie(nonce),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted", renewalNonce: nonce });
	});

	it("refuses, not_live (renewed), a cookie whose record moved to another nonce by the last reading", async () => {
		const nonce = newRenewalNonce();
		const inner = await holding(nonce);
		let reads = 0;
		const moving: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				reads += 1;
				return session === null || reads === 1
					? session
					: { ...session, renewalNonce: newRenewalNonce() };
			},
		};
		expect(
			await admitSession(withRequirement(moving), { claim: cookie(nonce), action: "test.use" }),
		).toEqual({ outcome: "not_live", reason: "renewed" });
		expect(reads).toBe(2);
	});

	it("carries the record's nonce for a code and a link carrier too", async () => {
		const nonce = newRenewalNonce();
		const store = await holding(nonce);
		for (const claim of [
			codeClaimRevalidation({ sid: SID }, SUB),
			linkClaim({ sid: SID, subject: SUB }),
		]) {
			expect(await admit(store, claim), claim.carrier).toMatchObject({
				outcome: "admitted",
				renewalNonce: nonce,
			});
		}
	});

	it("carries none for a non-cookie carrier over a stored value that is not a nonce", async () => {
		const inner = await holding();
		const odd: UserSessionStore = {
			...inner,
			get: async (sid) => {
				const session = await inner.get(sid);
				return session === null ? null : { ...session, renewalNonce: "not-a-nonce" };
			},
		};
		for (const claim of [
			tokenClaim({ sid: SID, sub: SUB }),
			codeClaimRevalidation({ sid: SID }, SUB),
			linkClaim({ sid: SID, subject: SUB }),
		]) {
			const admission = await admit(odd, claim);
			expect(admission, claim.carrier).toMatchObject({ outcome: "admitted" });
			expect(Object.hasOwn(admission, "renewalNonce"), claim.carrier).toBe(false);
		}
	});

	it("carries the record's nonce for a token carrier too, whose cookie is never compared", async () => {
		const nonce = newRenewalNonce();
		expect(
			await admitSession(deps(await holding(nonce)), {
				claim: tokenClaim({ sid: SID, sub: SUB }),
				action: "test.use",
			}),
		).toMatchObject({ outcome: "admitted", renewalNonce: nonce });
	});
});
