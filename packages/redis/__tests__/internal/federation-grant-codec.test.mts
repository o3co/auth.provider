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

// How a federation grant's authorization and credential are written down (ADR
// 2026-09-17-federation-grants-offline-delegation, D16).
//
// Every encoding is a wire format: the canonical authorization text is what
// the HASH stores AND what the credential's authenticated data is computed
// from, so the same authorization must produce the same bytes in this
// process, in another replica, and after a restart. Hence an array of strings
// with no property names, a date as a decimal millisecond string rather than
// a number, and nothing sorted, normalized or re-serialized on the way out.

import { createHash } from "node:crypto";
import type {
	FederationGrantAuthorization,
	FederationGrantCredentials,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	CREDENTIAL_EXTENSION_MAX_TEXT,
	canonicalAuthorization,
	credentialAad,
	credentialDigest,
	credentialExtensionAad,
	decodeCredentialExtension,
	decodeCredentials,
	encodeCredentialExtension,
	encodeCredentials,
	parseCanonicalAuthorization,
} from "#/internal/federation-grant-codec.mjs";

const T0 = 1_789_000_000_137;
const at = (ms: number): Date => new Date(T0 + ms);
const SCOPES = ["openid", "offline_access", "calendar.read"];

const authorization = (
	over: Partial<FederationGrantAuthorization> = {},
): FederationGrantAuthorization => ({
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	upstream: { issuer: "https://dev-1.okta.test", subject: "00u-alice" },
	resource: undefined,
	scopes: [...SCOPES],
	consent: { at: at(60_000), sid: "sid-1", scopes: [...SCOPES] },
	authorizedAt: at(120_000),
	expiresAt: at(30 * 86_400_000),
	...over,
});

const record = {
	credentialKey: "fg:{g-1}:cred",
	id: "g-1",
	subject: "u-1",
	clientId: "agent",
	connection: "okta-calendar",
};

const aad = (authorizationText: string, over: Partial<typeof record> = {}): string =>
	credentialAad({ ...record, ...over, authorization: authorizationText }).toString("utf8");

describe("the canonical authorization text", () => {
	it("is a flat array of strings with the dates as milliseconds: no property names to order, no numbers to format", () => {
		expect(canonicalAuthorization(authorization())).toBe(
			JSON.stringify([
				"identity-1",
				"authorization-1",
				"https://dev-1.okta.test",
				"00u-alice",
				[],
				SCOPES,
				String(T0 + 60_000),
				"sid-1",
				SCOPES,
				String(T0 + 120_000),
				String(T0 + 30 * 86_400_000),
			]),
		);
	});

	it("comes back as what went in, and the text it comes back from is the text it produces", () => {
		for (const over of [
			{},
			{ resource: "https://api.example.test/calendar" },
			{ scopes: [] },
			{ scopes: ["openid", "openid"] },
			{ consent: { at: at(1), sid: "", scopes: [] } },
		] satisfies Partial<FederationGrantAuthorization>[]) {
			const original = authorization(over);
			const text = canonicalAuthorization(original);
			const parsed = parseCanonicalAuthorization(text);
			expect(parsed, JSON.stringify(over)).toStrictEqual(original);
			expect(canonicalAuthorization(parsed as FederationGrantAuthorization)).toBe(text);
		}
	});

	it('tells an absent resource from an empty one: `[]` is not `[""]`', () => {
		const absent = canonicalAuthorization(authorization());
		const empty = canonicalAuthorization(authorization({ resource: "" }));
		expect(absent).not.toBe(empty);
		// Named and `undefined`, where the empty one holds "".
		expect(parseCanonicalAuthorization(absent)).toHaveProperty("resource", undefined);
		expect(parseCanonicalAuthorization(empty)?.resource).toBe("");
	});

	it("keeps the scopes as they were granted: order and duplicates are part of the record, not noise", () => {
		const one = canonicalAuthorization(authorization({ scopes: ["a", "b"] }));
		const other = canonicalAuthorization(authorization({ scopes: ["b", "a"] }));
		const twice = canonicalAuthorization(authorization({ scopes: ["a", "a", "b"] }));
		expect(new Set([one, other, twice]).size).toBe(3);
		expect(parseCanonicalAuthorization(twice)?.scopes).toStrictEqual(["a", "a", "b"]);
	});

	it("survives what a separator-joined encoding would not: the separator itself, quotes, control characters, a lone surrogate", () => {
		for (const hostile of [
			'","',
			'\\","',
			"[]",
			`a${String.fromCharCode(0)}b`,
			"a\nb",
			"\u{1f510}",
			"\ud800",
			"日本語",
		]) {
			const original = authorization({
				identityRevision: hostile,
				scopes: [hostile, ""],
				consent: { at: at(1), sid: hostile, scopes: [hostile] },
			});
			const text = canonicalAuthorization(original);
			expect(parseCanonicalAuthorization(text), JSON.stringify(hostile)).toStrictEqual(original);
		}
	});

	it("is refused rather than guessed at when it is not that shape: a field missing, a date that is not one, another JSON value", () => {
		const good = JSON.parse(canonicalAuthorization(authorization())) as unknown[];
		const cases: Record<string, string> = {
			"not JSON": "{",
			"an object": '{"identityRevision":"x"}',
			"a shorter array": JSON.stringify(good.slice(0, 10)),
			"a longer array": JSON.stringify([...good, "extra"]),
			"a date that is not a number": JSON.stringify(good.with(6, "not-a-date")),
			"a date as a JSON number": JSON.stringify(good.with(6, T0)),
			"a fractional date": JSON.stringify(good.with(6, "1.5")),
			"scopes that are not strings": JSON.stringify(good.with(5, [1])),
			"scopes that are not an array": JSON.stringify(good.with(5, "openid")),
			"a resource that is neither absent nor present": JSON.stringify(good.with(4, ["a", "b"])),
			"an issuer that is not a string": JSON.stringify(good.with(2, null)),
		};
		for (const [name, text] of Object.entries(cases)) {
			expect(parseCanonicalAuthorization(text), name).toBeUndefined();
		}
	});
});

describe("the credential's authenticated data", () => {
	it("binds the key it is stored under together with the record's identity and every authorization field", () => {
		const text = canonicalAuthorization(authorization());
		expect(aad(text)).toBe(
			JSON.stringify([
				"o3co.auth-provider.federation-grant",
				1,
				"fg:{g-1}:cred",
				"g-1",
				"u-1",
				"agent",
				"okta-calendar",
				text,
			]),
		);
	});

	it("changes when any one of those changes, and not otherwise", () => {
		const text = canonicalAuthorization(authorization());
		const base = aad(text);
		const changed = [
			aad(text, { credentialKey: "fg:{g-2}:cred" }),
			aad(text, { id: "g-2" }),
			aad(text, { subject: "u-2" }),
			aad(text, { clientId: "other-agent" }),
			aad(text, { connection: "okta-mail" }),
			aad(canonicalAuthorization(authorization({ identityRevision: "identity-2" }))),
			aad(canonicalAuthorization(authorization({ authorizationRevision: "authorization-2" }))),
			aad(
				canonicalAuthorization(
					authorization({ upstream: { issuer: "https://evil.test", subject: "00u-alice" } }),
				),
			),
			aad(
				canonicalAuthorization(
					authorization({ upstream: { issuer: "https://dev-1.okta.test", subject: "00u-bob" } }),
				),
			),
			aad(canonicalAuthorization(authorization({ scopes: [...SCOPES, "mail.send"] }))),
			aad(canonicalAuthorization(authorization({ resource: "https://api.example.test" }))),
			aad(
				canonicalAuthorization(
					authorization({ consent: { at: at(61_000), sid: "sid-1", scopes: [...SCOPES] } }),
				),
			),
			aad(
				canonicalAuthorization(
					authorization({ consent: { at: at(60_000), sid: "sid-2", scopes: [...SCOPES] } }),
				),
			),
			aad(
				canonicalAuthorization(
					authorization({ consent: { at: at(60_000), sid: "sid-1", scopes: ["openid"] } }),
				),
			),
			aad(canonicalAuthorization(authorization({ authorizedAt: at(121_000) }))),
			aad(canonicalAuthorization(authorization({ expiresAt: at(31 * 86_400_000) }))),
		];
		expect(new Set(changed).size).toBe(changed.length);
		expect(changed).not.toContain(base);
		// The same authorization twice is the same bytes: a replica that seals and
		// one that opens are different processes.
		expect(aad(canonicalAuthorization(authorization()))).toBe(base);
	});

	it("cannot be made to collide by moving a separator between two fields", () => {
		// Without JSON's own escaping, a subject ending in the separator and a
		// client ID beginning with it would encode the same as the other way
		// round. The one encoding is what each array element is.
		const text = canonicalAuthorization(authorization());
		expect(aad(text, { subject: 'u-1","agent', clientId: "" })).not.toBe(
			aad(text, { subject: "u-1", clientId: "agent" }),
		);
	});
});

describe("the credential payload", () => {
	const credentials = (
		over: Partial<FederationGrantCredentials> = {},
	): FederationGrantCredentials => ({
		refreshToken: "rt-1",
		accessToken: {
			value: "at-1",
			tokenType: "Bearer",
			obtainedAt: at(120_000),
			issuedLifetime: 3600,
			scopes: [...SCOPES],
		},
		...over,
	});

	it("comes back as what went in, with the access token and without it", () => {
		// With the key named and `undefined`: what the store hands back when
		// there is no access token.
		const refreshOnly = credentials({ accessToken: undefined });
		for (const input of [credentials(), refreshOnly]) {
			const text = encodeCredentials(input);
			expect(decodeCredentials(text)).toStrictEqual(input);
			expect(encodeCredentials(decodeCredentials(text) as FederationGrantCredentials)).toBe(text);
		}
	});

	it("keeps a lifetime that is not a whole number of seconds, and a zero, exactly as the upstream issued it", () => {
		const token = credentials().accessToken as NonNullable<
			FederationGrantCredentials["accessToken"]
		>;
		for (const issuedLifetime of [0, 1, 0.5, 3599.999, Number.MAX_SAFE_INTEGER]) {
			const input = credentials({ accessToken: { ...token, issuedLifetime } });
			expect(decodeCredentials(encodeCredentials(input)), String(issuedLifetime)).toStrictEqual(
				input,
			);
		}
	});

	it("is refused rather than guessed at when it is not that shape", () => {
		const good = JSON.parse(encodeCredentials(credentials())) as unknown[];
		const cases: Record<string, string> = {
			"not JSON": "}",
			"an object": '{"refreshToken":"rt-1"}',
			"an unknown format": JSON.stringify(good.with(0, 2)),
			"no refresh token": JSON.stringify(good.with(1, null)),
			"an empty refresh token": JSON.stringify(good.with(1, "")),
			"an access token that is neither absent nor present": JSON.stringify(good.with(2, [[], []])),
			"an access token missing a field": JSON.stringify(good.with(2, [["at-1", "Bearer"]])),
			"a lifetime that is not a number": JSON.stringify(
				good.with(2, [["at-1", "Bearer", String(T0), "later", []]]),
			),
			"a date that is not one": JSON.stringify(good.with(2, [["at-1", "Bearer", "x", "1", []]])),
		};
		for (const [name, text] of Object.entries(cases)) {
			expect(decodeCredentials(text), name).toBeUndefined();
		}
	});
});

describe("the credential's extension", () => {
	const binding = { ...record, authorization: canonicalAuthorization(authorization()) };
	const ENVELOPE = "v2.ay1h.aXYtaXYtaXYtaXY.Y2lwaGVy.dGFnLXRhZy10YWctdGFn";

	it("names the exact credential envelope it was written with, as the base64url SHA-256 of its bytes", () => {
		expect(credentialDigest(ENVELOPE)).toBe(
			createHash("sha256").update(ENVELOPE, "utf8").digest("base64url"),
		);
		expect(credentialDigest(ENVELOPE)).not.toBe(credentialDigest(`${ENVELOPE}x`));
	});

	it("is authenticated under its own label, the credential's whole binding and that envelope's digest", () => {
		expect(JSON.parse(credentialExtensionAad(binding, ENVELOPE).toString("utf8"))).toStrictEqual([
			"o3co.auth-provider.federation-grant-ext",
			1,
			binding.credentialKey,
			binding.id,
			binding.subject,
			binding.clientId,
			binding.connection,
			binding.authorization,
			credentialDigest(ENVELOPE),
		]);
	});

	it("never shares authenticated data with the credential, and changes with every field it binds", () => {
		const base = credentialExtensionAad(binding, ENVELOPE).toString("utf8");
		expect(base).not.toBe(credentialAad(binding).toString("utf8"));
		for (const over of [
			{ credentialKey: "fg:{g-2}:cred" },
			{ id: "g-2" },
			{ subject: "u-2" },
			{ clientId: "other" },
			{ connection: "other" },
			{ authorization: canonicalAuthorization(authorization({ authorizationRevision: "a-2" })) },
		]) {
			expect(credentialExtensionAad({ ...binding, ...over }, ENVELOPE).toString("utf8")).not.toBe(
				base,
			);
		}
		expect(credentialExtensionAad(binding, `${ENVELOPE}x`).toString("utf8")).not.toBe(base);
	});

	it("is written only when it has a key to carry: the end as a decimal millisecond string, and the binding when given", () => {
		expect(encodeCredentialExtension({})).toBeUndefined();
		expect(encodeCredentialExtension({ effectiveExpiresAt: undefined })).toBeUndefined();
		expect(encodeCredentialExtension({ effectiveExpiresAt: at(1_800_000) })).toBe(
			JSON.stringify({ effectiveExpiresAt: String(T0 + 1_800_000) }),
		);
		expect(encodeCredentialExtension({ effectiveExpiresAt: at(1_800_000) }, "digest")).toBe(
			JSON.stringify({ bind: "digest", effectiveExpiresAt: String(T0 + 1_800_000) }),
		);
		expect(encodeCredentialExtension({}, "digest")).toBeUndefined();
	});

	it("comes back as what went in", () => {
		const text = encodeCredentialExtension({ effectiveExpiresAt: at(1_800_000) }, "digest");
		expect(decodeCredentialExtension(text as string)).toStrictEqual({
			bind: "digest",
			effectiveExpiresAt: at(1_800_000),
		});
	});

	it("reads only the keys it knows, into a fresh object, and ignores every other", () => {
		const read = decodeCredentialExtension(
			JSON.stringify({
				future: { anything: 1 },
				effectiveExpiresAt: String(T0),
				constructor: "x",
				toString: "x",
			}),
		);
		expect(read).toStrictEqual({ effectiveExpiresAt: new Date(T0) });
		expect(Object.getPrototypeOf(read)).toBe(Object.prototype);
		const proto = decodeCredentialExtension(
			`{"__proto__":{"effectiveExpiresAt":"${T0}","bind":"x"}}`,
		);
		expect(proto).toStrictEqual({});
		expect(proto?.effectiveExpiresAt).toBeUndefined();
		expect(({} as { effectiveExpiresAt?: unknown }).effectiveExpiresAt).toBeUndefined();
	});

	it.each([
		["not JSON", "{"],
		["JSON null", "null"],
		["an array", `["${T0}"]`],
		["a string", `"${T0}"`],
		["a number", String(T0)],
		["text past the bound", JSON.stringify({ pad: "x".repeat(CREDENTIAL_EXTENSION_MAX_TEXT) })],
	])("reads as no extension at all when it is %s", (_, text) => {
		expect(decodeCredentialExtension(text)).toBeUndefined();
	});

	it.each([
		["a JSON number", T0],
		["a fraction", `${T0}.5`],
		["an exponent", "1e12"],
		["blank", ""],
		["past the Date range", "8640000000000001"],
		["before the Date range", "-8640000000000001"],
		["past the safe integers", "9007199254740993"],
		["an object", { at: String(T0) }],
	])("reads an end that is %s as no end", (_, value) => {
		expect(decodeCredentialExtension(JSON.stringify({ effectiveExpiresAt: value }))).toStrictEqual(
			{},
		);
	});

	it("keeps an end at either edge of the Date range, and one at or before any start: judging it is core's", () => {
		for (const ms of [8_640_000_000_000_000, -8_640_000_000_000_000, 0]) {
			expect(
				decodeCredentialExtension(JSON.stringify({ effectiveExpiresAt: String(ms) }))
					?.effectiveExpiresAt,
			).toStrictEqual(new Date(ms));
		}
	});

	it("reads a binding that is not a string as no binding", () => {
		expect(decodeCredentialExtension(JSON.stringify({ bind: 7 }))).toStrictEqual({});
	});
});
