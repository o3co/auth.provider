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

import fs from "node:fs";
import bcrypt from "bcrypt";
import yaml from "js-yaml";
import type { ClientRepository } from "./ClientRepository.mjs";
import type { Client } from "./types.mjs";

interface ClientEntry {
	clientSecret: string;
	allowedRedirectUris: string[];
	allowedScopes: string[];
}

export class StaticClientRepository implements ClientRepository {
	private clients: Map<string, ClientEntry>;

	constructor(filePath: string) {
		const content = fs.readFileSync(filePath, "utf-8");
		const data = yaml.load(content) as Record<string, ClientEntry> | null;
		this.clients = new Map(Object.entries(data ?? {}));
	}

	async findById(clientId: string): Promise<Client | null> {
		const entry = this.clients.get(clientId);
		if (!entry) return null;
		return {
			clientId,
			clientSecret: entry.clientSecret,
			allowedRedirectUris: entry.allowedRedirectUris ?? [],
			allowedScopes: entry.allowedScopes ?? [],
		};
	}

	async authenticate(clientId: string, secret: string): Promise<Client | null> {
		const client = await this.findById(clientId);
		if (!client) return null;

		const stored = client.clientSecret;
		const isBcrypt = stored.startsWith("$2b$");

		const match = isBcrypt
			? await bcrypt.compare(secret, stored)
			: secret === stored;

		return match ? client : null;
	}
}
