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
import { federationGrantRedirectUriReservedParameter } from "../federation-grants/lodge.mjs";
import { isLoopbackHostname } from "../net/loopback.mjs";
import { checkRedirectUri, describeRedirectUriRejection } from "../net/redirect-uri.mjs";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";
import {
	assertRegistrableClientIds,
	isWellFormedClientId,
	MAX_CLIENT_ID_LENGTH,
} from "./clientId.mjs";

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
 * The members a public JWK never carries (RFC 7518 §6.2.2, §6.3.2, §6.4):
 * a registration is the client's *public* keys, and one that smuggles the
 * private half in would expose it through the `PublicClient` projection.
 */
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** One public JWK: a `kty`, asymmetric, and none of the private members. */
const publicJwkSchema = z.record(z.string(), z.unknown()).superRefine((jwk, ctx) => {
	if (typeof jwk.kty !== "string" || jwk.kty.length === 0) {
		ctx.addIssue({ code: z.ZodIssueCode.custom, message: "jwks.keys[]: a JWK requires kty" });
		return;
	}
	if (jwk.kty === "oct") {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message: 'jwks.keys[]: kty "oct" is a symmetric key; register public keys only',
		});
		return;
	}
	const leaked = PRIVATE_JWK_MEMBERS.filter((member) => member in jwk);
	if (leaked.length > 0) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message: `jwks.keys[]: private key material (${leaked.join(", ")}) must not be registered; publish the public key only`,
		});
	}
});

/**
 * Where a `private_key_jwt` client publishes its keys: `https`, or `http` on
 * a loopback host for local development, like every other operator-registered
 * URL in this schema. Operator configuration, not request input.
 */
const jwksUriSchema = z
	.string()
	.url()
	.refine(
		(value) => {
			try {
				const url = new URL(value);
				return (
					url.protocol === "https:" ||
					(url.protocol === "http:" && isLoopbackHostname(url.hostname))
				);
			} catch {
				return false;
			}
		},
		{ message: "jwksUri must be an https URL (plain http only on a loopback host)" },
	);

/**
 * A registered-redirect-URI list, each entry held to the shared
 * `net/redirect-uri` grammar, a refusal reported as `field[index]` and the
 * rule broken. The rule's wording comes from the checker, so a custom
 * `ClientRepository` opting into `checkRedirectUri` refuses in the same
 * words.
 *
 * Shared by `allowedRedirectUris` and `postLogoutRedirectUris`, the two lists
 * of URIs a user agent is sent to.
 *
 * A refusal never quotes the URI: its query can carry a token or a
 * credential someone registered by mistake, and the message reaches a boot
 * error and the boundary's log line. The position finds the entry.
 *
 * @internal
 */
const redirectUriListSchema = (field: string) =>
	z.array(z.string()).superRefine((uris, ctx) => {
		uris.forEach((uri, index) => {
			const rejection = checkRedirectUri(uri);
			if (rejection !== null) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message: `${field}[${index}]: ${describeRedirectUriRejection(rejection)}`,
					path: [index],
				});
			}
		});
	});

/**
 * The fields of a client registration other than its secret and its id,
 * each held to its own rule. An entry adds the secret
 * ({@link ClientEntrySchema}); a record a repository answers adds the id
 * ({@link PublicClientRecordSchema}).
 */
const registrationFields = z.object({
	// RFC 6749 §2.3 / RFC 7591 §2 client authentication method. The
	// registration's rules below require `clientSecret` for confidential
	// methods and refuse it for `"none"` wherever the secret is held.
	tokenEndpointAuthMethod: z.enum([
		"client_secret_basic",
		"client_secret_post",
		"private_key_jwt",
		"none",
	]),
	// The key sources for `private_key_jwt`: exactly one of the two for that
	// method, neither for any other (superRefine below).
	jwks: z.object({ keys: z.array(publicJwkSchema).min(1) }).optional(),
	jwksUri: jwksUriSchema.optional(),
	// Held to the registered-redirect-URI grammar (net/redirect-uri.mts) at
	// boot: a `javascript:` target, a fragment, userinfo, plain http off
	// loopback, and a query name outside the allowlist or one the
	// authorization response appends are refused.
	allowedRedirectUris: redirectUriListSchema("allowedRedirectUris").default([]),
	allowedScopes: z.array(z.string()).default([]),
	// What an omitted `scope` parameter grants. Absent plus a non-empty
	// allowlist makes a scope-omitting request `invalid_scope`
	// (deny-by-absence). Must be ⊆ allowedScopes (superRefine below).
	defaultScopes: z.array(z.string()).optional(),
	// `""` matches nothing, but `generateToken` would stamp `aud: ""` on every
	// token minted for this client, so it is refused at registration.
	allowedAudiences: z.array(z.string().min(1)).default([]),
	// Per-client grant type allowlist. Absent means no restriction on
	// authorization_code and refresh_token; grants that declare
	// `requiresExplicitGrantAllowlist` (client_credentials, WebAuthn) are
	// deny-by-absence at /token dispatch.
	allowedGrantTypes: z.array(z.string()).optional(),
	// Logout metadata.
	//
	// `postLogoutRedirectUris` uses the same checker as `allowedRedirectUris`:
	// it is a URI a user agent is redirected to, so it takes the redirect-target
	// grammar. A custom scheme (`com.example.app:/signout`) is allowed; a
	// fragment (RFC 6749 §3.1.2), userinfo, control characters and `http:` off
	// a loopback host are refused.
	postLogoutRedirectUris: redirectUriListSchema("postLogoutRedirectUris").optional(),
	// The other two logout fields stay on `httpUrlSchema` deliberately: neither
	// is a redirect target. `backchannelLogoutUri` is POSTed by this server and
	// `frontchannelLogoutUri` is rendered as an iframe `src`; a custom scheme is
	// meaningless to the first and dangerous in the second, where the browser
	// resolves it in a document context.
	backchannelLogoutUri: httpUrlSchema.optional(),
	// Defaults to `true`, unlike OIDC Back-Channel Logout 1.0 §2.2 (`false`
	// when omitted): `sid` in logout_token mitigates CSRF / session confusion
	// where RPs cannot otherwise correlate logouts. Set `false` explicitly for
	// the spec default. Discovery must advertise
	// `backchannel_logout_session_supported` and
	// `frontchannel_logout_session_supported` as `true`.
	backchannelLogoutSessionRequired: z.boolean().optional().default(true),
	frontchannelLogoutUri: httpUrlSchema.optional(),
	frontchannelLogoutSessionRequired: z.boolean().optional().default(true),
	// Federation-token access opt-in; deny by default.
	allowedAzpForFederationToken: z.boolean().optional().default(false),
	// Which federation grant connections this client may spend a grant on, and
	// where a connect flow may return to. Absent means none of either. Names are
	// compared exactly, so nothing is trimmed, folded or sorted; duplicates are
	// refused at boot rather than deduplicated.
	allowedFederationGrantConnections: z
		.array(z.string().regex(/^[A-Za-z0-9_-]+$/, "must be a connection name"))
		.optional(),
	federationGrantRedirectUris: z.array(z.string().min(1)).optional(),
	// /authorize admits only `firstParty: true` clients. Absent means "not
	// first-party": the marking is opt-in.
	firstParty: z.boolean().optional(),
	// What the consent page shows for a client that is not first-party.
	clientName: z.string().min(1).optional(),
	// Rendered as a link on the consent page, so held to http(s):
	// `z.string().url()` admits `javascript:` and `data:`.
	clientUri: httpUrlSchema.optional(),
	// The only way to reach the RFC 7636 `plain` challenge method. No default:
	// absent must stay distinguishable from an explicit `false` in the surfaced
	// record; both mean "S256 only" at the policy site.
	allowPlainPkce: z.boolean().optional(),
	// Per-client sender-constraint requirement. `methods` entries are
	// non-empty so a typo cannot match a future mechanism with `kind: ""`; the
	// superRefine below refuses `required: true` with no methods.
	senderConstrained: z
		.object({
			required: z.boolean(),
			methods: z.array(z.string().min(1)).readonly(),
		})
		.readonly()
		.optional(),
});

/** A registration's fields as {@link checkRegistration} judges them. */
type Registration = z.output<typeof registrationFields> & { readonly clientSecret?: string };

/**
 * The registration's rules across its fields. `secretHeld` says whether the
 * value holds the registration's secret (an entry) or never does (a
 * `PublicClient`): a secret that must be there is missed only where it
 * could be.
 */
function checkRegistration(data: Registration, ctx: z.RefinementCtx, secretHeld: boolean): void {
	// defaultScopes ⊆ allowedScopes: otherwise omitting `scope` would grant
	// more than any scope-carrying request could.
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
	// Confidential clients (basic / post) must carry a secret. Public clients
	// (`"none"`) must not: a secret left in config invites an operator to assume
	// the client is confidential. A record a repository answers never holds the
	// secret, so only an entry is judged for a missing one.
	const needsSecret =
		data.tokenEndpointAuthMethod === "client_secret_basic" ||
		data.tokenEndpointAuthMethod === "client_secret_post";
	if (secretHeld && needsSecret && data.clientSecret === undefined) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message:
				'clientSecret is required when tokenEndpointAuthMethod is "client_secret_basic" or "client_secret_post"',
			path: ["clientSecret"],
		});
	}
	// A grant is a confidential client's to hold: the credential it spends
	// belongs to a user, and a public client cannot keep one.
	for (const field of [
		"allowedFederationGrantConnections",
		"federationGrantRedirectUris",
	] as const) {
		const value = data[field];
		if (data.tokenEndpointAuthMethod === "none" && value !== undefined && value.length > 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `${field} must not be set for a public client (tokenEndpointAuthMethod "none")`,
				path: [field],
			});
		}
		if (value !== undefined && new Set(value).size !== value.length) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `${field} must not repeat a value`,
				path: [field],
			});
		}
	}
	// Each refusal names the entry by its position, never by the URI, as
	// `redirectUriListSchema` does.
	(data.federationGrantRedirectUris ?? []).forEach((uri, index) => {
		const rejection = checkRedirectUri(uri);
		if (rejection !== null) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `federationGrantRedirectUris[${index}]: ${rejection.reason}`,
				path: ["federationGrantRedirectUris", index],
			});
		}
		// The end of a grant flow appends these; refused at boot rather than when
		// a user is waiting.
		const reserved = federationGrantRedirectUriReservedParameter(uri);
		if (reserved !== undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					`federationGrantRedirectUris[${index}]: already carries "${reserved}" (compared ignoring ` +
					'case, "_" and "-"), which the end of a grant flow appends — the client would receive ' +
					"it twice",
				path: ["federationGrantRedirectUris", index],
			});
		}
	});
	if (data.tokenEndpointAuthMethod === "none" && data.clientSecret !== undefined) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message: 'clientSecret must not be set when tokenEndpointAuthMethod is "none"',
			path: ["clientSecret"],
		});
	}
	// private_key_jwt proves possession of a key, so it carries keys and no
	// secret; every other method carries no keys.
	const hasKeys = data.jwks !== undefined;
	const hasKeysUri = data.jwksUri !== undefined;
	if (data.tokenEndpointAuthMethod === "private_key_jwt") {
		if (hasKeys === hasKeysUri) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					'tokenEndpointAuthMethod "private_key_jwt" requires exactly one of jwks (inline public keys) or jwksUri',
				path: ["jwks"],
			});
		}
		if (data.clientSecret !== undefined) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					'clientSecret must not be set when tokenEndpointAuthMethod is "private_key_jwt" — the client proves possession of its private key instead of presenting a shared secret',
				path: ["clientSecret"],
			});
		}
	} else if (hasKeys || hasKeysUri) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message:
				'jwks and jwksUri are only meaningful when tokenEndpointAuthMethod is "private_key_jwt"',
			path: [hasKeys ? "jwks" : "jwksUri"],
		});
	}
	// `required: true` with no methods would reject every binding at runtime;
	// fail at boot instead.
	if (data.senderConstrained?.required === true && data.senderConstrained.methods.length === 0) {
		ctx.addIssue({
			code: z.ZodIssueCode.custom,
			message: "senderConstrained.methods must contain at least one kind when required is true",
			path: ["senderConstrained", "methods"],
		});
	}
}

/**
 * @internal
 *
 * Zod schema for client entries consumed by the in-memory and YAML client
 * repositories; not public API. Exported only to share fixtures with unit
 * tests in this package. Core's client-record boundary
 * (`validatedClientRepository`) holds a record any `ClientRepository`
 * answers to the same rules ({@link PublicClientRecordSchema}).
 */
export const ClientEntrySchema = registrationFields
	.extend({ clientSecret: z.string().min(1).optional() })
	.strict()
	.superRefine((data, ctx) => checkRegistration(data, ctx, true));

/**
 * @internal
 *
 * A client record as a `ClientRepository` answers it (`PublicClient`): the
 * registration's fields and rules, with its id and without its secret, the
 * defaults filled as for an entry. What core's boundary
 * (`clientRepositoryBoundary.mts`) holds every answer to; not public API.
 */
export const PublicClientRecordSchema = registrationFields
	.extend({
		// The rule a registered id is held to at boot (`assertRegistrableClientIds`)
		// and a requested one before the repository is asked: an id no request
		// could name is not a client's. Never quoted: it may hold a control
		// character.
		clientId: z.string().refine(isWellFormedClientId, {
			message: `must be 1 to ${MAX_CLIENT_ID_LENGTH} characters with no control character`,
		}),
	})
	.strict()
	.superRefine((data, ctx) => checkRegistration(data, ctx, false));

export type ClientEntry = z.infer<typeof ClientEntrySchema>;

export class InMemoryClientRepository implements ClientRepository {
	private clients: Map<string, ClientEntry>;

	constructor(clients: Map<string, ClientEntry>) {
		// A client registered under an id no request can name could never be
		// used: every route screens `client_id` first (`clientId.mts`).
		assertRegistrableClientIds("InMemoryClientRepository", clients.keys());
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
			...(entry.allowedFederationGrantConnections !== undefined && {
				allowedFederationGrantConnections: entry.allowedFederationGrantConnections,
			}),
			...(entry.federationGrantRedirectUris !== undefined && {
				federationGrantRedirectUris: entry.federationGrantRedirectUris,
			}),
			...(entry.jwks !== undefined && { jwks: entry.jwks }),
			...(entry.jwksUri !== undefined && { jwksUri: entry.jwksUri }),
			...(entry.senderConstrained !== undefined && {
				senderConstrained: entry.senderConstrained,
			}),
			...(entry.firstParty !== undefined && {
				firstParty: entry.firstParty,
			}),
			...(entry.clientName !== undefined && { clientName: entry.clientName }),
			...(entry.clientUri !== undefined && { clientUri: entry.clientUri }),
			...(entry.allowPlainPkce !== undefined && {
				allowPlainPkce: entry.allowPlainPkce,
			}),
		};
	}

	async authenticate(clientId: string, secret: string): Promise<PublicClient | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;

		// Public clients have no secret to check. `clientAuthMw` already routes
		// them to `findById`; this guard makes the contract structural. Returning
		// null, not throwing, keeps the failure indistinguishable from a wrong
		// secret so the timing surface stays uniform.
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
			...(entry.allowedFederationGrantConnections !== undefined && {
				allowedFederationGrantConnections: entry.allowedFederationGrantConnections,
			}),
			...(entry.federationGrantRedirectUris !== undefined && {
				federationGrantRedirectUris: entry.federationGrantRedirectUris,
			}),
			...(entry.jwks !== undefined && { jwks: entry.jwks }),
			...(entry.jwksUri !== undefined && { jwksUri: entry.jwksUri }),
			...(entry.senderConstrained !== undefined && {
				senderConstrained: entry.senderConstrained,
			}),
			...(entry.firstParty !== undefined && {
				firstParty: entry.firstParty,
			}),
			...(entry.clientName !== undefined && { clientName: entry.clientName }),
			...(entry.clientUri !== undefined && { clientUri: entry.clientUri }),
			...(entry.allowPlainPkce !== undefined && {
				allowPlainPkce: entry.allowPlainPkce,
			}),
		};
	}
}
