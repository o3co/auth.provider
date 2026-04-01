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

export const ClientEntrySchema = z
	.object({
		clientSecret: z.string().min(1),
		allowedRedirectUris: z.array(z.string()).default([]),
		allowedScopes: z.array(z.string()).default([]),
	})
	.strict();

export type ClientEntry = z.infer<typeof ClientEntrySchema>;

export class InMemoryClientRepository implements ClientRepository {
	private clients: Map<string, ClientEntry>;

	constructor(clients: Map<string, ClientEntry>) {
		this.clients = clients;
	}

	async findById(clientId: string): Promise<PublicClient | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;
		return {
			clientId,
			allowedRedirectUris: entry.allowedRedirectUris,
			allowedScopes: entry.allowedScopes,
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
		};
	}
}
