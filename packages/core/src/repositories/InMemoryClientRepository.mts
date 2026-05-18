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
		allowedRedirectUris: z.array(z.string()).default([]),
		allowedScopes: z.array(z.string()).default([]),
		allowedAudiences: z.array(z.string()).default([]),
		// Wave 1 §3.4.1: per-client grant type allowlist. Absent means no restriction on
		// existing grants (authorization_code, refresh_token). client_credentials is gated
		// by deny-by-absence — see createClientCredentialsGrant handler.
		allowedGrantTypes: z.array(z.string()).optional(),
		// NEW (TODO-F-5): Logout metadata.
		// Use httpUrlSchema (not z.string().url()) for fields that end up in iframe src
		// or redirect targets — rejects javascript:, data:, file: to prevent XSS.
		postLogoutRedirectUris: z.array(httpUrlSchema).optional(),
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
		};
	}
}
