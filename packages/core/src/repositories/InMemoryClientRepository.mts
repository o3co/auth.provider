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

import crypto from "node:crypto";
import bcrypt from "bcrypt";
import { z } from "zod";
import { checkRedirectUri, describeRedirectUriRejection } from "../net/redirect-uri.mjs";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";

/**
 * Validates that a URL string uses only `http:` or `https:` schemes.
 * Rejects `javascript:`, `data:`, `file:`, and other dangerous schemes that
 * could enable XSS when embedded in `<iframe src="...">` (front-channel logout)
 * or used in redirect flows.
 *
 * @internal — shared only with unit tests in this package.
 */
const httpUrlSchema = z
	.string()
	.url()
	.refine(
		(u) => {
			try {
				const scheme = new URL(u).protocol;
				return scheme === "https:" || scheme === "http:";
			} catch {
				// new URL() threw — the string is not a valid absolute URL;
				// z.string().url() already rejects it, so return false here too.
				return false;
			}
		},
		{ message: "URL must use http: or https: scheme" },
	);

/**
 * One entry of a registered-redirect-URI list, held to the shared
 * `net/redirect-uri` grammar and reporting refusals under `field`.
 *
 * Parameterised by the field name so `allowedRedirectUris` and
 * `postLogoutRedirectUris` — the two lists on this record whose entries are
 * URIs a *user agent* is sent to — are one vocabulary rather than two. The
 * refusal wording comes from the checker, so a custom `ClientRepository`
 * opting into `checkRedirectUri` refuses in the same words.
 *
 * @internal
 */
const redirectUriEntrySchema = (field: string) =>
	z.string().superRefine((uri, ctx) => {
		const rejection = checkRedirectUri(uri);
		if (rejection !== null) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `${field} entry ${JSON.stringify(uri)}: ${describeRedirectUriRejection(rejection)}`,
			});
		}
	});

/**
 * @internal
 *
 * Zod schema for per-client configuration entries consumed by the in-memory and
 * YAML client repositories. NOT part of the public API — consumers implementing
 * a custom `ClientRepository` should define their own input schema suited to
 * their backing store (database row, JWT claims, LDAP attributes, etc.).
 * This schema is exported only to share fixtures with unit tests within the
 * package.
 */
export const ClientEntrySchema = z
	.object({
		// D-6 (v0.5.1): RFC 6749 §2.3 / RFC 7591 §2 client authentication method.
		// Required — `clientSecret` is now optional and gated by the superRefine
		// below so confidential clients still surface a startup error when the
		// secret is missing, and public clients (`"none"`) cannot smuggle a
		// secret in.
		tokenEndpointAuthMethod: z.enum(["client_secret_basic", "client_secret_post", "none"]),
		clientSecret: z.string().min(1).optional(),
		// #395: held to the registered-redirect-URI shape (net/redirect-uri.mts)
		// at boot — a `javascript:` target, a fragment, userinfo, or plain http
		// off loopback used to register cleanly and become a valid redirect.
		// The logout URL fields below were already URL-validated; the more
		// dangerous surface now is too. Refusal wording comes from the checker,
		// so a custom ClientRepository opting in refuses in the same words.
		allowedRedirectUris: z.array(redirectUriEntrySchema("allowedRedirectUris")).default([]),
		allowedScopes: z.array(z.string()).default([]),
		// #396: what an omitted `scope` parameter grants. Optional — absent plus a
		// non-empty allowlist makes a scope-omitting request `invalid_scope`
		// (deny-by-absence; the old behavior granted the ENTIRE allowlist). Held
		// to ⊆ allowedScopes by the superRefine below: a default the allowlist
		// would refuse is a misconfiguration, not a grant.
		defaultScopes: z.array(z.string()).optional(),
		allowedAudiences: z.array(z.string()).default([]),
		// Wave 1 §3.4.1: per-client grant type allowlist. Absent means no restriction on
		// existing grants (authorization_code, refresh_token). Grants that declare
		// `requiresExplicitGrantAllowlist` (client_credentials, WebAuthn) are gated by
		// deny-by-absence at /token dispatch (#326).
		allowedGrantTypes: z.array(z.string()).optional(),
		// NEW (TODO-F-5): Logout metadata.
		//
		// #498: `postLogoutRedirectUris` uses the SAME checker as
		// `allowedRedirectUris` above, and for the same reason — it is a URI a
		// user agent is redirected to, so it wants the redirect-target grammar,
		// not "is this an http URL". On `httpUrlSchema` an app whose only
		// redirect target is a reverse-DNS custom scheme (`com.example.app:/
		// signout`) could register where it receives the authorization response
		// and NOT where it is sent afterwards, so RP-initiated logout ended in a
		// JSON body instead of back in the app.
		//
		// The move also TIGHTENS this field: `checkRedirectUri` refuses a
		// fragment (RFC 6749 §3.1.2), userinfo, control characters and plain
		// `http:` off a loopback host, all of which `httpUrlSchema` admitted.
		// That is the same list `allowedRedirectUris` has been held to since
		// #395; a post-logout target is not the weaker surface.
		postLogoutRedirectUris: z.array(redirectUriEntrySchema("postLogoutRedirectUris")).optional(),
		// The other two logout fields deliberately STAY on `httpUrlSchema`, and
		// are not a drift from the line above. Neither is a redirect target:
		// `backchannelLogoutUri` is fetched by this server as an RFC-defined
		// POST, and `frontchannelLogoutUri` is rendered as an iframe `src`. A
		// custom scheme is meaningless to the first (nothing here can dispatch
		// `com.example.app:` — an OS handler can) and actively dangerous in the
		// second, where the browser resolves the value in a document context.
		// http/https is the whole vocabulary either one has.
		backchannelLogoutUri: httpUrlSchema.optional(),
		// NOTE: OIDC Back-Channel Logout 1.0 §2.2 defines backchannel_logout_session_required
		// as defaulting to `false` when omitted. This implementation intentionally defaults to
		// `true` to include `sid` in logout_token by default, which mitigates CSRF / session-
		// confusion risk for self-hosted deployments where RPs often cannot correlate logouts
		// without sid. Clients that want the spec-default behavior must set the field explicitly
		// to `false`. The OIDC Discovery metadata (`backchannel_logout_session_supported`,
		// `frontchannel_logout_session_supported`) must advertise `true` — see Task 7.
		backchannelLogoutSessionRequired: z.boolean().optional().default(true),
		frontchannelLogoutUri: httpUrlSchema.optional(),
		frontchannelLogoutSessionRequired: z.boolean().optional().default(true),
		// NEW (TODO-F-6): Federation-token access opt-in. Default false — deny-by-default.
		allowedAzpForFederationToken: z.boolean().optional().default(false),
		// #316: /authorize admits only `firstParty: true` clients, and #330 removed
		// the migration flag that used to admit unmarked ones. This schema is
		// `.strict()`, so without the key a YAML/static registration could neither
		// carry the marking (unrecognized key → boot error) nor go without it
		// (unmarked → every /authorize returns unauthorized_client): the file-backed
		// adapters had no working configuration at all. Absent still means "not
		// first-party" — the marking is deliberately opt-in.
		firstParty: z.boolean().optional(),
		// #273: the ONLY way to reach the RFC 7636 `plain` challenge method.
		// Optional with no default, because absent must stay distinguishable
		// from an explicit `false` in the record the repositories surface, and
		// both mean "S256 only" at the policy site.
		allowPlainPkce: z.boolean().optional(),
		// Wave 2 §4.8: per-client sender-constraint requirement.
		// `methods` is `string().min(1)` so accidental empty kinds (typos
		// or trailing-comma artifacts) cannot silently match a future
		// mechanism with `kind: ""`. `superRefine` below rejects the
		// degenerate `required:true + methods:[]` combo at boot rather
		// than letting it fail-closed at every request.
		senderConstrained: z
			.object({
				required: z.boolean(),
				methods: z.array(z.string().min(1)).readonly(),
			})
			.readonly()
			.optional(),
	})
	.strict()
	.superRefine((data, ctx) => {
		// #396: defaultScopes ⊆ allowedScopes, at boot. An entry outside the
		// allowlist could never be granted to a scope-CARRYING request; letting
		// it ride the omitted-scope path would make omission the wider grant.
		if (data.defaultScopes !== undefined) {
			const outside = data.defaultScopes.filter((s) => !data.allowedScopes.includes(s));
			if (outside.length > 0) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `defaultScopes entries not in allowedScopes: ${outside.join(" ")}`,
					path: ["defaultScopes"],
				});
			}
		}
		// D-6 (v0.5.1): the discriminator must select the right credential shape.
		// Confidential clients (basic / post) must carry a secret; public clients
		// (`"none"`) MUST NOT — accepting a secret on a `"none"` client would leave
		// the credential in config where an operator could later assume the client
		// had been promoted to confidential without changing the auth method.
		const needsSecret =
			data.tokenEndpointAuthMethod === "client_secret_basic" ||
			data.tokenEndpointAuthMethod === "client_secret_post";
		if (needsSecret && data.clientSecret === undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					'clientSecret is required when tokenEndpointAuthMethod is "client_secret_basic" or "client_secret_post"',
				path: ["clientSecret"],
			});
		}
		if (!needsSecret && data.clientSecret !== undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: 'clientSecret must not be set when tokenEndpointAuthMethod is "none"',
				path: ["clientSecret"],
			});
		}
		// Wave 2 §4.8: `required: true` with an empty `methods` list
		// would reject every binding at runtime and is almost certainly
		// operator error. Fail at boot instead so misconfiguration is
		// surfaced immediately.
		if (data.senderConstrained?.required === true && data.senderConstrained.methods.length === 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: "senderConstrained.methods must contain at least one kind when required is true",
				path: ["senderConstrained", "methods"],
			});
		}
	});

export type ClientEntry = z.infer<typeof ClientEntrySchema>;

export class InMemoryClientRepository implements ClientRepository {
	private clients: Map<string, ClientEntry>;

	constructor(clients: Map<string, ClientEntry>) {
		// Parse each entry through the schema to enforce defaults (e.g. backchannelLogoutSessionRequired
		// and frontchannelLogoutSessionRequired default to `true`).
		this.clients = new Map(
			Array.from(clients.entries()).map(([id, entry]) => [id, ClientEntrySchema.parse(entry)]),
		);
	}

	async findById(clientId: string): Promise<PublicClient | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;
		return {
			clientId,
			tokenEndpointAuthMethod: entry.tokenEndpointAuthMethod,
			allowedRedirectUris: entry.allowedRedirectUris,
			allowedScopes: entry.allowedScopes,
			defaultScopes: entry.defaultScopes,
			allowedAudiences: entry.allowedAudiences,
			...(entry.allowedGrantTypes !== undefined && {
				allowedGrantTypes: entry.allowedGrantTypes,
			}),
			...(entry.postLogoutRedirectUris !== undefined && {
				postLogoutRedirectUris: entry.postLogoutRedirectUris,
			}),
			...(entry.backchannelLogoutUri !== undefined && {
				backchannelLogoutUri: entry.backchannelLogoutUri,
			}),
			backchannelLogoutSessionRequired: entry.backchannelLogoutSessionRequired,
			...(entry.frontchannelLogoutUri !== undefined && {
				frontchannelLogoutUri: entry.frontchannelLogoutUri,
			}),
			frontchannelLogoutSessionRequired: entry.frontchannelLogoutSessionRequired,
			allowedAzpForFederationToken: entry.allowedAzpForFederationToken,
			...(entry.senderConstrained !== undefined && {
				senderConstrained: entry.senderConstrained,
			}),
			...(entry.firstParty !== undefined && {
				firstParty: entry.firstParty,
			}),
			...(entry.allowPlainPkce !== undefined && {
				allowPlainPkce: entry.allowPlainPkce,
			}),
		};
	}

	async authenticate(clientId: string, secret: string): Promise<PublicClient | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;

		// D-6 (v0.5.1): public clients have no `clientSecret` to authenticate
		// against. `clientAuthMw` already routes them through `findById` instead
		// of `authenticate` — but this guard makes the contract structural rather
		// than relying on every caller to dispatch correctly. Returning null
		// (rather than throwing) keeps the failure indistinguishable from
		// "wrong secret" so the timing surface stays uniform.
		if (entry.tokenEndpointAuthMethod === "none" || entry.clientSecret === undefined) {
			return null;
		}

		const stored = entry.clientSecret;
		const isBcrypt = /^\$2[aby]\$/.test(stored);

		let match: boolean;
		if (isBcrypt) {
			match = await bcrypt.compare(secret, stored);
		} else {
			const a = Buffer.from(secret);
			const b = Buffer.from(stored);
			match = a.length === b.length && crypto.timingSafeEqual(a, b);
		}

		if (!match) return null;

		return {
			clientId,
			tokenEndpointAuthMethod: entry.tokenEndpointAuthMethod,
			allowedRedirectUris: entry.allowedRedirectUris,
			allowedScopes: entry.allowedScopes,
			defaultScopes: entry.defaultScopes,
			allowedAudiences: entry.allowedAudiences,
			...(entry.allowedGrantTypes !== undefined && {
				allowedGrantTypes: entry.allowedGrantTypes,
			}),
			...(entry.postLogoutRedirectUris !== undefined && {
				postLogoutRedirectUris: entry.postLogoutRedirectUris,
			}),
			...(entry.backchannelLogoutUri !== undefined && {
				backchannelLogoutUri: entry.backchannelLogoutUri,
			}),
			backchannelLogoutSessionRequired: entry.backchannelLogoutSessionRequired,
			...(entry.frontchannelLogoutUri !== undefined && {
				frontchannelLogoutUri: entry.frontchannelLogoutUri,
			}),
			frontchannelLogoutSessionRequired: entry.frontchannelLogoutSessionRequired,
			allowedAzpForFederationToken: entry.allowedAzpForFederationToken,
			...(entry.senderConstrained !== undefined && {
				senderConstrained: entry.senderConstrained,
			}),
			...(entry.firstParty !== undefined && {
				firstParty: entry.firstParty,
			}),
			...(entry.allowPlainPkce !== undefined && {
				allowPlainPkce: entry.allowPlainPkce,
			}),
		};
	}
}
