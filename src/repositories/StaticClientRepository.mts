/*
 * Copyright 2026 1o1 Inc.
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
import fs from "node:fs";
import bcrypt from "bcrypt";
import yaml from "js-yaml";
import { z } from "zod";
import type { ClientRepository, PublicClient } from "./ClientRepository.mjs";

const ClientEntrySchema = z.object({
	clientSecret: z.string().min(1),
	allowedRedirectUris: z.array(z.string()).default([]),
	allowedScopes: z.array(z.string()).default([]),
});

type ClientEntry = z.infer<typeof ClientEntrySchema>;

export class StaticClientRepository implements ClientRepository {
	private clients: Map<string, ClientEntry>;

	constructor(filePath: string) {
		const content = fs.readFileSync(filePath, "utf-8");
		const raw = yaml.load(content);
		if (raw !== null && raw !== undefined && (typeof raw !== "object" || Array.isArray(raw))) {
			throw new Error(`Invalid client configuration in ${filePath}: expected a YAML mapping`);
		}
		const data = (raw ?? {}) as Record<string, unknown>;
		this.clients = new Map<string, ClientEntry>();
		for (const [clientId, entry] of Object.entries(data)) {
			const result = ClientEntrySchema.safeParse(entry);
			if (!result.success) {
				throw new Error(
					`Invalid client entry "${clientId}" in ${filePath}: ${result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join(", ")}`,
				);
			}
			this.clients.set(clientId, result.data);
		}
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
