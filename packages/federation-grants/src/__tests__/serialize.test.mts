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
 * Core's result union rendered as HTTP (#593, D11).
 *
 * Every row of D11's table, in one place and as an exhaustive switch, so that
 * a code added to the union is a compile error here rather than a 500 in
 * production. The table is the contract a client is written against: which
 * failures are worth retrying (503, 429), which mean the user has to be asked
 * again (410), and which are the caller's own fault (400, 403, 404).
 */

import type {
	FederationGrantReauthorizationResult,
	FederationGrantTokenResult,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import {
	serializeFederationGrantLodgingRefusal,
	serializeFederationGrantTokenResult,
} from "#/serialize.mjs";

describe("serializeFederationGrantTokenResult", () => {
	it("renders a disclosed token as an OAuth token response and nothing else", () => {
		const rendered = serializeFederationGrantTokenResult({
			ok: true,
			accessToken: "upstream-access-token",
			tokenType: "Bearer",
			expiresIn: 1800,
			scopes: ["openid", "Files.Read"],
			refreshed: true,
		});
		expect(rendered.status).toBe(200);
		// `refreshed` is orchestration, not the caller's business: it says
		// whether this call paid for the upstream round trip, and a client that
		// branched on it would be branching on another caller's timing.
		expect(rendered.body).toEqual({
			access_token: "upstream-access-token",
			token_type: "Bearer",
			expires_in: 1800,
			scope: "openid Files.Read",
		});
	});

	it("keeps the upstream's spelling of the token type", () => {
		// Lower-cased by one library, capitalised by another; RFC 6749 §7.1
		// makes it case-insensitive, and a client comparing it exactly should
		// see what the upstream said rather than what this route preferred.
		const rendered = serializeFederationGrantTokenResult({
			ok: true,
			accessToken: "t",
			tokenType: "bearer",
			expiresIn: 0,
			scopes: [],
			refreshed: false,
		});
		expect(rendered.body).toMatchObject({ token_type: "bearer", expires_in: 0, scope: "" });
	});

	it("maps every denial in the union to the status D11 gives it", () => {
		const rows: readonly [FederationGrantTokenResult, number, string | undefined][] = [
			[{ ok: false, code: "grant_not_found" }, 404, undefined],
			[{ ok: false, code: "authorization_pending" }, 400, undefined],
			[
				{ ok: false, code: "grant_expired", reason: "consented_lifetime" },
				410,
				"consented_lifetime",
			],
			[{ ok: false, code: "grant_expired", reason: "operator_maximum" }, 410, "operator_maximum"],
			[{ ok: false, code: "grant_revoked", reason: "subject" }, 410, "subject"],
			[{ ok: false, code: "grant_revoked", reason: "backstop" }, 410, "backstop"],
			[{ ok: false, code: "connection_identity_changed" }, 410, undefined],
			[
				{ ok: false, code: "reauthorization_required", reason: "credential_unreadable" },
				410,
				"credential_unreadable",
			],
			[
				{ ok: false, code: "access_denied", reason: "connection_not_permitted" },
				403,
				"connection_not_permitted",
			],
			[
				{ ok: false, code: "invalid_request", reason: "min_ttl_out_of_range" },
				400,
				"min_ttl_out_of_range",
			],
			[{ ok: false, code: "invalid_scope" }, 400, undefined],
			[{ ok: false, code: "invalid_target" }, 400, undefined],
			[
				{ ok: false, code: "upstream_token_ineligible", reason: "scope_exceeded" },
				502,
				"scope_exceeded",
			],
			[{ ok: false, code: "upstream_rejected", reason: "invalid_client" }, 502, "invalid_client"],
			[{ ok: false, code: "rate_limited", reason: "upstream" }, 429, "upstream"],
			[{ ok: false, code: "temporarily_unavailable", reason: "storage" }, 503, "storage"],
			[
				{ ok: false, code: "temporarily_unavailable", reason: "key_unavailable" },
				503,
				"key_unavailable",
			],
		];
		for (const [result, status, description] of rows) {
			const rendered = serializeFederationGrantTokenResult(result);
			expect(rendered.status, JSON.stringify(result)).toBe(status);
			expect(rendered.body, JSON.stringify(result)).toEqual(
				description === undefined
					? { error: (result as { code: string }).code }
					: { error: (result as { code: string }).code, error_description: description },
			);
		}
	});

	it("carries Retry-After for every denial that came with one, not only a throttle", () => {
		// A 502 from an ineligible upstream token and a 503 from a lock that
		// timed out both know when it is worth asking again. A client told only
		// by the 429 retries the other two immediately, for ever.
		for (const result of [
			{
				ok: false,
				code: "upstream_token_ineligible",
				reason: "scope_exceeded",
				retryAfterSeconds: 300,
			},
			{ ok: false, code: "upstream_rejected", reason: "invalid_grant", retryAfterSeconds: 30 },
			{ ok: false, code: "rate_limited", reason: "upstream", retryAfterSeconds: 60 },
			{ ok: false, code: "temporarily_unavailable", reason: "lock_timeout", retryAfterSeconds: 5 },
		] as const) {
			const rendered = serializeFederationGrantTokenResult(result);
			expect(rendered.retryAfterSeconds, JSON.stringify(result)).toBe(result.retryAfterSeconds);
		}
	});

	it("invents no wait where the union carried none", () => {
		const rendered = serializeFederationGrantTokenResult({
			ok: false,
			code: "temporarily_unavailable",
			reason: "storage",
		});
		expect(rendered.retryAfterSeconds).toBeUndefined();
	});

	it("answers the three ownership failures with one byte-identical body", () => {
		// An unknown id, a grant belonging to another client and one belonging
		// to another subject are the same answer, so that a caller cannot
		// enumerate grant ids or discover whose they are.
		const rendered = serializeFederationGrantTokenResult({ ok: false, code: "grant_not_found" });
		expect(JSON.stringify(rendered.body)).toBe('{"error":"grant_not_found"}');
	});
});

describe("serializeFederationGrantLodgingRefusal", () => {
	type Refusal = Exclude<FederationGrantReauthorizationResult, { ok: true }>;
	const refusal = (fields: Record<string, unknown>) => ({ ok: false, ...fields }) as Refusal;

	it("renders every refusal lodging can give as D6's exit for it", () => {
		const rows: [Record<string, unknown>, number, Record<string, string>][] = [
			[
				{ reason: "connection_not_permitted" },
				403,
				{ error: "access_denied", error_description: "connection_not_permitted" },
			],
			[
				{ reason: "connection_not_configured" },
				503,
				{ error: "temporarily_unavailable", error_description: "connection_not_configured" },
			],
			[
				{ reason: "storage" },
				503,
				{ error: "temporarily_unavailable", error_description: "storage" },
			],
			[
				{ reason: "key_unavailable" },
				503,
				{ error: "temporarily_unavailable", error_description: "key_unavailable" },
			],
			[
				{ reason: "redirect_uri_not_registered" },
				400,
				{ error: "invalid_request", error_description: "redirect_uri_not_registered" },
			],
			[
				{ reason: "redirect_uri_invalid" },
				400,
				{ error: "invalid_request", error_description: "redirect_uri_invalid" },
			],
			[
				{ reason: "redirect_uri_reserved_parameter" },
				400,
				{ error: "invalid_request", error_description: "redirect_uri_reserved_parameter" },
			],
			[
				{ reason: "expires_in_out_of_range" },
				400,
				{ error: "invalid_request", error_description: "expires_in_out_of_range" },
			],
			[
				{ reason: "connection_mismatch" },
				400,
				{ error: "invalid_request", error_description: "connection_mismatch" },
			],
			[
				{ reason: "scope_exceeded" },
				400,
				{ error: "invalid_scope", error_description: "scope_exceeded" },
			],
			[
				{ reason: "openid_required" },
				400,
				{ error: "invalid_scope", error_description: "openid_required" },
			],
			[
				{ reason: "offline_access_required" },
				400,
				{ error: "invalid_scope", error_description: "offline_access_required" },
			],
			[
				{ reason: "scope_subsets_not_allowed" },
				400,
				{ error: "invalid_scope", error_description: "scope_subsets_not_allowed" },
			],
			[
				{ reason: "intent_limit" },
				429,
				{ error: "rate_limited", error_description: "intent_limit" },
			],
			[{ reason: "grant_not_found" }, 404, { error: "grant_not_found" }],
			[{ reason: "authorization_pending" }, 400, { error: "authorization_pending" }],
			[
				{ reason: "grant_revoked", revokedBy: "backstop", revokedNow: false },
				410,
				{ error: "grant_revoked", error_description: "backstop" },
			],
			[
				{ reason: "grant_expired", expiredBy: "operator_maximum" },
				410,
				{ error: "grant_expired", error_description: "operator_maximum" },
			],
			[{ reason: "connection_identity_changed" }, 410, { error: "connection_identity_changed" }],
			[
				{ reason: "upstream_token_ineligible", ineligibleBy: "lifetime_over_maximum" },
				502,
				{ error: "upstream_token_ineligible", error_description: "lifetime_over_maximum" },
			],
		];
		for (const [fields, status, body] of rows) {
			expect(
				serializeFederationGrantLodgingRefusal(refusal(fields)),
				String(fields.reason),
			).toEqual({
				status,
				body,
			});
		}
	});

	it("never renders the record a backstop revocation returned", () => {
		const rendered = serializeFederationGrantLodgingRefusal(
			refusal({
				reason: "grant_revoked",
				revokedBy: "backstop",
				revokedNow: true,
				revoked: { id: "g-1", subject: "u-1", clientId: "agent" },
			}),
		);
		expect(rendered).toEqual({
			status: 410,
			body: { error: "grant_revoked", error_description: "backstop" },
		});
	});
});
