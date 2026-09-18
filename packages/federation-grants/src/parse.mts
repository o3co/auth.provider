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
 * can see.
 */

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
	/** `description` is the stable identifier the 400 carries, never prose. */
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
	if (Array.isArray(value)) return { ok: false, description: `${field} was given more than once` };
	if (typeof value !== "string") return { ok: false, description: `${field} must be a string` };
	return { ok: true, value };
};

export function parseFederationGrantTokenRequest(body: unknown): ParsedFederationGrantTokenRequest {
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return refuse("the request body must be a JSON object or a form body");
	}
	const fields = body as Record<string, unknown>;
	for (const field of Object.keys(fields)) {
		if (!KNOWN.has(field)) return refuse(`${field} is not a parameter of this request`);
	}

	const subRead = single(fields.sub, "sub");
	if (!subRead.ok) return refuse(subRead.description);
	// Exactly as written: the comparison against the grant's owner is exact,
	// and trimming or case-folding here would authorise a subject the store
	// never recorded.
	const sub = subRead.value;
	if (sub === undefined || sub === "") return refuse("sub is required");

	const connectionRead = single(fields.connection, "connection");
	if (!connectionRead.ok) return refuse(connectionRead.description);
	const connection = connectionRead.value;
	if (connection === "") return refuse("connection must not be empty");

	const resourceRead = single(fields.resource, "resource");
	if (!resourceRead.ok) return refuse(resourceRead.description);
	const resource = resourceRead.value;
	if (resource === "") return refuse("resource must not be empty");

	const scopeRead = single(fields.scope, "scope");
	if (!scopeRead.ok) return refuse(scopeRead.description);
	const scopeText = scopeRead.value;
	let scope: readonly string[] | undefined;
	if (scopeText !== undefined) {
		// RFC 6749 §3.3: space-delimited. Split without sorting, widening or
		// supplying defaults — the set is exactly what the caller asked for.
		const tokens = scopeText.split(" ").filter((token) => token !== "");
		if (tokens.length === 0) return refuse("scope must name at least one scope");
		scope = tokens;
	}

	let minTtlSeconds: number | undefined;
	const rawMinTtl = fields.min_ttl;
	if (rawMinTtl !== undefined) {
		if (Array.isArray(rawMinTtl)) return refuse("min_ttl was given more than once");
		if (typeof rawMinTtl === "object" && rawMinTtl !== null) {
			return refuse("min_ttl must be a number");
		}
		// A JSON number, or the decimal a form body carries it as. `Number("")`
		// is 0 and `Number("60s")` is NaN, and both are refusals rather than
		// values core would have to have an opinion about.
		const parsed = typeof rawMinTtl === "number" ? rawMinTtl : Number(String(rawMinTtl).trim());
		if (rawMinTtl === "" || !Number.isFinite(parsed)) {
			return refuse("min_ttl must be a number of seconds");
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
	if (typeof body !== "object" || body === null || Array.isArray(body)) {
		return refuse("the request body must be a JSON object or a form body");
	}
	for (const field of Object.keys(body as Record<string, unknown>)) {
		if (STATUS_KNOWN.has(field)) continue;
		if (KNOWN.has(field)) {
			return refuse(`${field} is a parameter of the token route, not of this one`);
		}
		return refuse(`${field} is not a parameter of this request`);
	}
	return parseFederationGrantTokenRequest(body);
}
