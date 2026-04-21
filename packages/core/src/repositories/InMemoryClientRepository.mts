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
		clientSecret: z.string().min(1),
		allowedRedirectUris: z.array(z.string()).default([]),
		allowedScopes: z.array(z.string()).default([]),
		// NEW (TODO-F-5): Logout metadata.
		postLogoutRedirectUris: z.array(z.string().url()).optional(),
		backchannelLogoutUri: z.string().url().optional(),
		// NOTE: OIDC Back-Channel Logout 1.0 §2.2 defines backchannel_logout_session_required
		// as defaulting to `false` when omitted. This implementation intentionally defaults to
		// `true` to include `sid` in logout_token by default, which mitigates CSRF / session-
		// confusion risk for self-hosted deployments where RPs often cannot correlate logouts
		// without sid. Clients that want the spec-default behavior must set the field explicitly
		// to `false`. The OIDC Discovery metadata (`backchannel_logout_session_supported`,
		// `frontchannel_logout_session_supported`) must advertise `true` — see Task 7.
		backchannelLogoutSessionRequired: z.boolean().optional().default(true),
		frontchannelLogoutUri: z.string().url().optional(),
		frontchannelLogoutSessionRequired: z.boolean().optional().default(true),
	})
	.strict();

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
			allowedRedirectUris: entry.allowedRedirectUris,
			allowedScopes: entry.allowedScopes,
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
		};
	}

	async authenticate(clientId: string, secret: string): Promise<PublicClient | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;

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
			allowedRedirectUris: entry.allowedRedirectUris,
			allowedScopes: entry.allowedScopes,
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
		};
	}
}
