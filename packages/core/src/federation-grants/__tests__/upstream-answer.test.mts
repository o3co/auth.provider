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

import { describe, expect, it } from "vitest";
import {
	type FederationGrantUpstreamAnswerContext,
	readFederationGrantUpstreamAnswer,
} from "#/federation-grants/upstream-answer.mjs";
import type { DelegatedTokens } from "#/federations/types.mjs";

const CALLED_AT = Date.UTC(2026, 8, 18, 1, 0, 0);
const RECEIVED_AT = CALLED_AT + 1_500;
const HOUR = 3_600_000;

const context: FederationGrantUpstreamAnswerContext = {
	calledAt: CALLED_AT,
	receivedAt: RECEIVED_AT,
	requestedScopes: ["openid", "calendar.read"],
	consentedScopes: ["openid", "offline_access", "calendar.read"],
	maxAccessTokenLifetime: 3600,
};

const answer = (over: Partial<Record<keyof DelegatedTokens, unknown>> = {}): DelegatedTokens =>
	({
		accessToken: "at-1",
		refreshToken: "rt-1",
		tokenType: "bearer",
		expiresIn: 3600,
		expiresAt: new Date(CALLED_AT + HOUR),
		scope: "openid calendar.read",
		...over,
	}) as DelegatedTokens;

const read = (value: unknown, over: Partial<FederationGrantUpstreamAnswerContext> = {}) =>
	readFederationGrantUpstreamAnswer(value, { ...context, ...over });

const refusedFor = (reason: string) => ({ eligible: false, reason });

describe("readFederationGrantUpstreamAnswer", () => {
	it("builds the token to store from an eligible answer: dated from the call, its type and scopes as answered", () => {
		expect(read(answer({ tokenType: "BEARER" }))).toStrictEqual({
			refreshToken: "rt-1",
			accessToken: {
				eligible: true,
				token: {
					value: "at-1",
					tokenType: "BEARER",
					obtainedAt: new Date(CALLED_AT),
					issuedLifetime: 3600,
					effectiveExpiresAt: new Date(CALLED_AT + HOUR),
					scopes: ["openid", "calendar.read"],
				},
			},
		});
	});

	describe("the scope", () => {
		it("is what the request asked for when the answer names none (RFC 6749 §5.1), as a copy", () => {
			const requestedScopes = ["openid"];
			const read_ = read(answer({ scope: undefined }), { requestedScopes });
			if (!read_.accessToken.eligible) throw new Error("refused");
			expect(read_.accessToken.token.scopes).toStrictEqual(["openid"]);
			expect(read_.accessToken.token.scopes).not.toBe(requestedScopes);
		});

		it("is read by RFC 6749 §3.3's grammar: any whitespace separates", () => {
			const read_ = read(answer({ scope: "openid\tcalendar.read\n" }));
			if (!read_.accessToken.eligible) throw new Error("refused");
			expect(read_.accessToken.token.scopes).toStrictEqual(["openid", "calendar.read"]);
		});

		it("is what the request asked for when the answer is blank: a blank scope names none, and is not a token that carries nothing", () => {
			for (const scope of ["", "  \t "]) {
				const read_ = read(answer({ scope }), { requestedScopes: ["openid"] });
				if (!read_.accessToken.eligible) throw new Error(`refused ${JSON.stringify(scope)}`);
				expect(read_.accessToken.token.scopes, JSON.stringify(scope)).toStrictEqual(["openid"]);
			}
		});

		it("named but naming no scope-token is a malformed answer: never the requested scopes", () => {
			for (const scope of ['"openid"', '\t"openid"']) {
				expect(read(answer({ scope })).accessToken, JSON.stringify(scope)).toStrictEqual(
					refusedFor("malformed_token_response"),
				);
			}
		});

		it("is judged before the token type: a wider scope with a token that is not bearer is scope_exceeded", () => {
			expect(
				read(answer({ scope: "openid files.readwrite", tokenType: "dpop" })).accessToken,
			).toStrictEqual(refusedFor("scope_exceeded"));
		});

		it("is refused beyond the consent: a token cannot be narrowed after the fact", () => {
			expect(read(answer({ scope: "openid files.readwrite" })).accessToken).toStrictEqual(
				refusedFor("scope_exceeded"),
			);
		});
	});

	describe("the token type", () => {
		it("is required (RFC 6749 §5.1): an answer without one is malformed, and is not taken for Bearer", () => {
			expect(read(answer({ tokenType: undefined })).accessToken).toStrictEqual(
				refusedFor("malformed_token_response"),
			);
		});

		it("is refused when it is not a bearer token", () => {
			expect(read(answer({ tokenType: "dpop" })).accessToken).toStrictEqual(
				refusedFor("token_type_unsupported"),
			);
		});
	});

	describe("an answer that is not what an adapter should report", () => {
		const garbage: Array<[string, Partial<Record<keyof DelegatedTokens, unknown>>]> = [
			["no access token", { accessToken: undefined }],
			["an empty access token", { accessToken: "" }],
			["an access token that is not a string", { accessToken: 42 }],
			["an empty token type", { tokenType: "" }],
			["a token type that is not a string", { tokenType: 7 }],
			["a lifetime that is a string", { expiresIn: "3600" }],
			["an expiry that is a number", { expiresAt: CALLED_AT + HOUR }],
			["an expiry that is a string", { expiresAt: "2026-09-18T02:00:00.000Z" }],
			["scopes as an array", { scope: ["openid", "calendar.read"] }],
		];
		for (const [what, over] of garbage) {
			it(`${what}: malformed, and the refresh token is still read`, () => {
				expect(read(answer(over))).toStrictEqual({
					refreshToken: "rt-1",
					accessToken: refusedFor("malformed_token_response"),
				});
			});
		}

		it("an answer that is not an object at all: malformed, with no refresh token", () => {
			for (const value of [undefined, null, "at-1", 42]) {
				expect(read(value), String(value)).toStrictEqual({
					refreshToken: undefined,
					accessToken: refusedFor("malformed_token_response"),
				});
			}
		});

		it("a refresh token that is not a usable string reads as none", () => {
			for (const refreshToken of [undefined, "", 42, null, {}]) {
				expect(read(answer({ refreshToken })).refreshToken, String(refreshToken)).toBeUndefined();
			}
		});
	});

	describe("a read that throws", () => {
		const throwing = (field: keyof DelegatedTokens): DelegatedTokens => {
			const value = answer();
			Object.defineProperty(value, field, {
				get() {
					throw new Error("a getter that throws");
				},
			});
			return value;
		};

		for (const field of ["accessToken", "tokenType", "expiresIn", "expiresAt", "scope"] as const) {
			it(`of ${field}: an ineligible answer (malformed), never an outage, and the refresh token is still read`, () => {
				expect(read(throwing(field))).toStrictEqual({
					refreshToken: "rt-1",
					accessToken: refusedFor("malformed_token_response"),
				});
			});
		}

		it("of the refresh token: none, and the access token is judged all the same", () => {
			const read_ = read(throwing("refreshToken"));
			expect(read_.refreshToken).toBeUndefined();
			expect(read_.accessToken.eligible).toBe(true);
		});

		it("of an expiry's type: malformed", () => {
			const expiresAt = new Proxy(new Date(CALLED_AT + HOUR), {
				getPrototypeOf() {
					throw new Error("a trap that throws");
				},
			});
			expect(read(answer({ expiresAt })).accessToken).toStrictEqual(
				refusedFor("malformed_token_response"),
			);
		});
	});

	describe("the lifetime", () => {
		const cases: Array<[string, Partial<Record<keyof DelegatedTokens, unknown>>, string]> = [
			["none at all", { expiresIn: null, expiresAt: null }, "no_finite_lifetime"],
			["a lifetime without the adapter's anchor", { expiresAt: null }, "no_finite_lifetime"],
			["an anchor without a lifetime", { expiresIn: undefined }, "no_finite_lifetime"],
			["an expiry already past", { expiresAt: new Date(0) }, "no_finite_lifetime"],
			[
				"an expiry that is a Date holding no instant",
				{ expiresAt: new Date(Number.NaN) },
				"no_finite_lifetime",
			],
			[
				"a lifetime over the maximum, beside an expiry that ends it sooner",
				{ expiresIn: 7200 },
				"lifetime_over_maximum",
			],
		];
		for (const [what, over, reason] of cases) {
			it(`${what}: ${reason}`, () => {
				expect(read(answer(over)).accessToken).toStrictEqual(refusedFor(reason));
			});
		}

		it("ends at the earlier of the two fields, and is judged as issued", () => {
			const read_ = read(answer({ expiresAt: new Date(CALLED_AT + HOUR + 1_500) }));
			if (!read_.accessToken.eligible) throw new Error("refused");
			expect(read_.accessToken.token).toMatchObject({
				issuedLifetime: 3600,
				effectiveExpiresAt: new Date(CALLED_AT + HOUR),
			});
		});
	});

	describe("one snapshot: each field read once, and nothing of the adapter's kept", () => {
		it("reads every field exactly once", () => {
			const reads = new Map<PropertyKey, number>();
			const counted = new Proxy(answer(), {
				get(target, key, receiver) {
					reads.set(key, (reads.get(key) ?? 0) + 1);
					return Reflect.get(target, key, receiver);
				},
			});
			expect(read(counted).accessToken.eligible).toBe(true);
			expect(Object.fromEntries(reads)).toStrictEqual({
				refreshToken: 1,
				accessToken: 1,
				tokenType: 1,
				expiresIn: 1,
				expiresAt: 1,
				scope: 1,
			});
		});

		it("stores an expiry of its own making, by the instant the answer's Date holds", () => {
			const expiresAt = new Date(CALLED_AT + HOUR / 2);
			const read_ = read(answer({ expiresAt }));
			if (!read_.accessToken.eligible) throw new Error("refused");
			expect(read_.accessToken.token.effectiveExpiresAt).toStrictEqual(expiresAt);
			expect(read_.accessToken.token.effectiveExpiresAt).not.toBe(expiresAt);
		});
	});
});
