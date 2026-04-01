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

import type { User } from "./types.mjs";
import type { UserRepository } from "./UserRepository.mjs";

export class HttpUserRepository implements UserRepository {
	private baseURL: string;
	private timeout: number;

	constructor({ baseURL, timeout }: { baseURL: string; timeout: number }) {
		this.baseURL = baseURL;
		this.timeout = timeout;
	}

	async authenticate(username: string, password: string): Promise<User | null> {
		return this.post("/user/authenticate", { email: username, password });
	}

	async authenticateByToken(token: string): Promise<User | null> {
		return this.post("/user/authenticate/token", { token });
	}

	private async post(endpoint: string, body: unknown): Promise<User | null> {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), this.timeout);

		try {
			const res = await fetch(`${this.baseURL}${endpoint}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(body),
				signal: controller.signal,
			});

			if (res.ok) {
				return (await res.json()) as User;
			}

			if (res.status === 401 || res.status === 403) {
				return null;
			}

			throw new Error(`Unexpected HTTP status ${res.status} from ${endpoint}`);
		} finally {
			clearTimeout(timer);
		}
	}
}
