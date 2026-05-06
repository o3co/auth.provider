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

import type { User, UserRepository } from "@o3co/auth-provider-core";

/**
 * Runtime guard for the upstream user-service response. The previous
 * `(await res.json()) as User` was a compile-time cast only — a malformed
 * upstream payload (`{ status: "ok" }`, schema migration, tampered
 * response) silently produced a `User` with `undefined` required fields,
 * leaking `sub: undefined` into the authentication flow.
 *
 * The guard accepts any object with string `id` and `username`,
 * preserving the index-signature `[key: string]: unknown` extras that
 * `User` allows. Empty strings pass — bcrypt compare and downstream
 * gates prevent empty-credential authentication in practice; tightening
 * to `.min(1)` is a Phase F follow-up if needed.
 *
 * Per TS-2 (Wave 5g).
 */
function isUser(v: unknown): v is User {
	if (typeof v !== "object" || v === null) return false;
	const o = v as Record<string, unknown>;
	return typeof o.id === "string" && typeof o.username === "string";
}

export class HttpUserRepository implements UserRepository {
	private authenticateUrl: string;
	private authenticateByTokenUrl: string;
	private timeout: number;

	constructor({
		authenticateUrl,
		authenticateByTokenUrl,
		timeout,
	}: {
		authenticateUrl: string;
		authenticateByTokenUrl: string;
		timeout: number;
	}) {
		this.authenticateUrl = authenticateUrl;
		this.authenticateByTokenUrl = authenticateByTokenUrl;
		this.timeout = timeout;
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		return this.post(this.authenticateUrl, { email: username, password });
	}

	async authenticateByToken(token: string): Promise<User | null> {
		return this.post(this.authenticateByTokenUrl, { token });
	}

	private async post(url: string, body: unknown): Promise<User | null> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeout);

		try {
			const res = await fetch(url, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
				signal: controller.signal,
			});

			if (res.ok) {
				const parsed: unknown = await res.json();
				if (!isUser(parsed)) {
					// Upstream returned 2xx with an unexpected shape — this is an
					// "upstream is broken" case, not a "user not found" case, so
					// throw rather than return null. The thrown error propagates
					// as a 500 to the client (correct: upstream-service failure).
					throw new Error(`HttpUserRepository: upstream ${url} returned an invalid User shape`);
				}
				return parsed;
			}

			if (res.status === 401 || res.status === 403) {
				return null;
			}

			throw new Error(`Unexpected HTTP status ${res.status} from ${url}`);
		} finally {
			clearTimeout(timer);
		}
	}
}
