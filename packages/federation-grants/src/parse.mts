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
 * The domain body of `POST /oauth/federation-grants/:grantId/token` (#593, D10).
 *
 * Every field is an *assertion*: something the caller claims about the grant
 * it is asking against, which core then checks against what was consented to.
 * None of them widens anything — asking for a scope the grant does not carry
 * is a refusal, never a request — so this hands core exactly what was written,
 * or refuses before core is asked at all.
 *
 * It deliberately does not judge `min_ttl`. Whether the number is negative, or
 * larger than the connection permits, is core's decision and comes back as
 * `invalid_request/min_ttl_out_of_range`: one answer to one question, rather
 * than two layers each carrying their own idea of a bound only one of them
 * can see. It does read `scope` by RFC 6749 §3.3's grammar, strictly: a value
 * that is not a space-delimited list of scope-tokens is not an assertion core
 * could check, and is refused here as `invalid_scope`.
 */

import { readSpaceDelimitedParameter } from "@o3co/auth-provider-core";

/** What the parse produces, in the shape `RetrieveFederationGrantTokenRequest` wants it. */
export interface FederationGrantTokenRequestBody {
	readonly subject: string;
	readonly connection?: string;
	readonly scope?: readonly string[];
	readonly resource?: string;
	readonly minTtlSeconds?: number;
}

export type ParsedFederationGrantTokenRequest =
	| { readonly ok: true; readonly value: FederationGrantTokenRequestBody }
	/**
	 * A stable identifier, and never prose (D9).
	 *
	 * It used to be a sentence — `"sub is required"` — which reads well and is
	 * useless: a caller that wants to branch on it has to match on English,
	 * and the day the wording improves every one of those callers breaks. The
	 * identifiers are `snake_case`, are part of the contract, and are what the
	 * exit tables in the README and the ADR list.
	 *
	 * The promise covers what **this package** answers. What it inherits —
	 * client authentication's 401s, the shared limiter's 503 — still carries
	 * that middleware's own wording, and rewriting it per route would make the
	 * same failure read differently on `/token` and on `/revoke`.
	 */
	| { readonly ok: false; readonly description: string };

/**
 * The fields this route reads, plus the ones client authentication reads out
 * of the same body. Anything else is refused rather than ignored: a caller
 * that wrote `scopes` for `scope`, or `subject` for `sub`, asked for something
 * that did not happen, and silence is how that goes unnoticed until it
 * matters.
 */
const KNOWN = new Set([
	"sub",
	"connection",
	"scope",
	"resource",
	"min_ttl",
	// RFC 6749 §2.3.1 / RFC 7523 §2.2, read by `createClientAuthMiddleware`.
	"client_id",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
]);

const refuse = (description: string): ParsedFederationGrantTokenRequest => ({
	ok: false,
	description,
});

/**
 * One value, or a refusal.
 *
 * An array is what a form body carrying the same parameter twice arrives as,
 * and neither value is the one the caller meant. Picking the first is how a
 * proxy and a server come to disagree about which subject was asked for.
 */
type Read =
	| { readonly ok: true; readonly value: string | undefined }
	| { readonly ok: false; readonly description: string };

const single = (value: unknown, field: string): Read => {
	if (value === undefined) return { ok: true, value: undefined };
	if (Array.isArray(value)) return { ok: false, description: `duplicate_${field}` };
	if (typeof value !== "string") return { ok: false, description: `invalid_${field}` };
	return { ok: true, value };
};

export function parseFederationGrantTokenRequest(body: unknown): ParsedFederationGrantTokenRequest {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return refuse("invalid_body");
	}
	const fields = body as Record<string, unknown>;
	for (const field of Object.keys(fields)) {
		// The field is deliberately not named: it is caller-supplied, and what
		// goes into `error_description` goes into logs and dashboards.
		if (!KNOWN.has(field)) return refuse("unexpected_parameter");
	}

	const subRead = single(fields.sub, "sub");
	if (!subRead.ok) return refuse(subRead.description);
	// Exactly as written: the comparison against the grant's owner is exact,
	// and trimming or case-folding here would authorise a subject the store
	// never recorded.
	const sub = subRead.value;
	if (sub === undefined || sub === "") return refuse("sub_required");

	const connectionRead = single(fields.connection, "connection");
	if (!connectionRead.ok) return refuse(connectionRead.description);
	const connection = connectionRead.value;
	if (connection === "") return refuse("invalid_connection");

	const resourceRead = single(fields.resource, "resource");
	if (!resourceRead.ok) return refuse(resourceRead.description);
	const resource = resourceRead.value;
	if (resource === "") return refuse("invalid_resource");

	const scopeRead = single(fields.scope, "scope");
	if (!scopeRead.ok) return refuse(scopeRead.description);
	const scopeText = scopeRead.value;
	let scope: readonly string[] | undefined;
	if (scopeText !== undefined) {
		// RFC 6749 §3.3, read strictly: the caller's assertion, so a value that
		// is not a space-delimited list of scope-tokens is refused rather than
		// asserting a scope named with a tab. Split without sorting, widening
		// or supplying defaults — the set is exactly what the caller asked for,
		// without repeats.
		const tokens = readSpaceDelimitedParameter(scopeText);
		if (tokens === null || tokens.length === 0) return refuse("invalid_scope");
		scope = tokens;
	}

	let minTtlSeconds: number | undefined;
	const rawMinTtl = fields.min_ttl;
	if (rawMinTtl !== undefined) {
		if (Array.isArray(rawMinTtl)) return refuse("duplicate_min_ttl");
		if (typeof rawMinTtl === "object" && rawMinTtl !== null) {
			return refuse("invalid_min_ttl");
		}
		// A JSON number, or the decimal a form body carries it as. `Number("")`
		// is 0 and `Number("60s")` is NaN, and both are refusals rather than
		// values core would have to have an opinion about.
		const parsed = typeof rawMinTtl === "number" ? rawMinTtl : Number(String(rawMinTtl).trim());
		if (rawMinTtl === "" || !Number.isFinite(parsed)) {
			return refuse("invalid_min_ttl");
		}
		minTtlSeconds = parsed;
	}

	return {
		ok: true,
		value: {
			subject: sub,
			...(connection === undefined ? {} : { connection }),
			...(scope === undefined ? {} : { scope }),
			...(resource === undefined ? {} : { resource }),
			...(minTtlSeconds === undefined ? {} : { minTtlSeconds }),
		},
	};
}

/** `sub`, plus the fields client authentication reads out of the same body. */
const STATUS_KNOWN = new Set([
	"sub",
	"client_id",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
]);

/**
 * The status route's body: `{"sub": "..."}` and nothing else.
 *
 * The token route's assertions are **refused** here rather than ignored. A
 * caller that sent `min_ttl` to `/status` asked a question this route does not
 * answer, and a 200 describing the grant would read as though it had — status
 * says what the grant IS, not what a token would be.
 */
export function parseFederationGrantStatusRequest(
	body: unknown,
): ParsedFederationGrantTokenRequest {
	return parseWithout(body, STATUS_KNOWN);
}

/** `sub`, plus the fields client authentication reads out of the same body. */
const REVOKE_KNOWN = STATUS_KNOWN;

/**
 * The revoke route's body: `{"sub": "..."}`, and the same refusal for anything
 * else.
 *
 * `scope`, `resource`, `connection` and `min_ttl` are conditions on a *token*.
 * A withdrawal has no conditions — the grant either belongs to this caller and
 * this subject or it does not — and accepting a field that reads like a
 * condition would suggest one was honoured.
 */
export function parseFederationGrantRevokeRequest(
	body: unknown,
): ParsedFederationGrantTokenRequest {
	return parseWithout(body, REVOKE_KNOWN);
}

/**
 * `sub` and the authentication fields, with every other parameter refused —
 * including the token route's own.
 *
 * One identifier for all of them, and deliberately: a caller that sent
 * `min_ttl` here and a caller that sent `minttl` both asked for something that
 * did not happen, and the difference between the two is not something to
 * branch on.
 */
function parseWithout(
	body: unknown,
	known: ReadonlySet<string>,
): ParsedFederationGrantTokenRequest {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return refuse("invalid_body");
	}
	for (const field of Object.keys(body as Record<string, unknown>)) {
		if (!known.has(field)) return refuse("unexpected_parameter");
	}
	return parseFederationGrantTokenRequest(body);
}

// ---------------------------------------------------------------------------
// Slice 6: lodging (D6)
// ---------------------------------------------------------------------------

/** What a lodging body says, in the shape core's lodging takes. */
export interface FederationGrantLodgingBody {
	readonly subject: string;
	/** Required on a first intent; on a renewal an assertion about the grant, and nothing more. */
	readonly connection?: string;
	readonly redirectUri: string;
	readonly clientState: string;
	readonly scope?: readonly string[];
	readonly expiresInSeconds?: number;
	readonly upstreamSubject?: string;
}

export type ParsedFederationGrantLodgingRequest =
	| { readonly ok: true; readonly value: FederationGrantLodgingBody }
	| { readonly ok: false; readonly description: string };

const LODGING_KNOWN = new Set([
	"sub",
	"connection",
	"redirect_uri",
	"state",
	"scope",
	"expires_in",
	"upstream_sub",
	"client_id",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
]);

const lodgingRefuse = (description: string): ParsedFederationGrantLodgingRequest => ({
	ok: false,
	description,
});

/**
 * A lifetime in whole seconds: a JSON number, or the plain decimal a form body
 * carries it as. Nothing that has to be interpreted to be read — no fraction,
 * no exponent, no hex, no boolean — and nothing past what a safe integer holds.
 * A request above the maximum is not refused here: core clamps it and the
 * answer says what applied.
 */
const seconds = (value: unknown): number | undefined => {
	const parsed =
		typeof value === "number"
			? value
			: typeof value === "string" && /^\d+$/.test(value)
				? Number(value)
				: Number.NaN;
	return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : undefined;
};

function parseLodging(
	body: unknown,
	requireConnection: boolean,
): ParsedFederationGrantLodgingRequest {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return lodgingRefuse("invalid_body");
	}
	const fields = body as Record<string, unknown>;
	for (const field of Object.keys(fields)) {
		// Refused rather than ignored, and not named: a caller that sent
		// `resource` or `expires_at` asked for something that will not happen.
		// Neither is a lodging parameter — the resource is the connection's, and
		// an expiry is dated from consent, which has not happened yet.
		if (!LODGING_KNOWN.has(field)) return lodgingRefuse("unexpected_parameter");
	}

	const read = (field: string): Read => single(fields[field], field);
	const sub = read("sub");
	if (!sub.ok) return lodgingRefuse(sub.description);
	if (sub.value === undefined || sub.value === "") return lodgingRefuse("sub_required");

	const connection = read("connection");
	if (!connection.ok) return lodgingRefuse(connection.description);
	if (connection.value === "") return lodgingRefuse("invalid_connection");
	if (requireConnection && connection.value === undefined)
		return lodgingRefuse("connection_required");

	const redirect = read("redirect_uri");
	if (!redirect.ok) return lodgingRefuse(redirect.description);
	if (redirect.value === undefined || redirect.value === "") {
		return lodgingRefuse("redirect_uri_required");
	}

	const state = read("state");
	if (!state.ok) return lodgingRefuse(state.description);
	// Required and not trimmed: the client binds it to its own session and
	// compares it on the way back, byte for byte.
	if (state.value === undefined || state.value === "") return lodgingRefuse("state_required");

	const scope = read("scope");
	if (!scope.ok) return lodgingRefuse(scope.description);
	let scopes: readonly string[] | undefined;
	if (scope.value !== undefined) {
		// Read strictly, as the token route reads its scope: malformed is
		// refused, not re-split or dropped. Present and empty is not "the
		// connection's full set" — that is what leaving it out says, and the
		// two must not be confused.
		const tokens = readSpaceDelimitedParameter(scope.value);
		if (tokens === null || tokens.length === 0) return lodgingRefuse("invalid_scope");
		scopes = tokens;
	}

	let expiresInSeconds: number | undefined;
	if (fields.expires_in !== undefined) {
		if (Array.isArray(fields.expires_in)) return lodgingRefuse("duplicate_expires_in");
		expiresInSeconds = seconds(fields.expires_in);
		if (expiresInSeconds === undefined) return lodgingRefuse("invalid_expires_in");
	}

	const upstream = read("upstream_sub");
	if (!upstream.ok) return lodgingRefuse(upstream.description);
	if (upstream.value === "") return lodgingRefuse("invalid_upstream_sub");

	return {
		ok: true,
		value: {
			subject: sub.value,
			...(connection.value === undefined ? {} : { connection: connection.value }),
			redirectUri: redirect.value,
			clientState: state.value,
			...(scopes === undefined ? {} : { scope: scopes }),
			...(expiresInSeconds === undefined ? {} : { expiresInSeconds }),
			...(upstream.value === undefined ? {} : { upstreamSubject: upstream.value }),
		},
	};
}

/** `POST /oauth/federation-grants`: `connection` is required. */
export function parseFederationGrantCreateRequest(
	body: unknown,
): ParsedFederationGrantLodgingRequest {
	return parseLodging(body, true);
}

/**
 * `POST /oauth/federation-grants/:grantId/reauthorize`: the connection is the
 * grant's. One sent anyway is an assertion, checked against the grant, and never
 * a way to move it to another connection.
 */
export function parseFederationGrantReauthorizeRequest(
	body: unknown,
): ParsedFederationGrantLodgingRequest {
	return parseLodging(body, false);
}
