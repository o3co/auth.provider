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
import { createClient, type RedisClientType } from "redis";
import type { CodeRepository } from "./CodeRepository.mjs";
import type { Code } from "./types.mjs";

const KEY_PREFIX = "oauth:code:";

export class RedisCodeRepository implements CodeRepository {
	private redis: RedisClientType;
	private defaultExpiresIn: number;

	constructor({
		endpointUri,
		password,
		defaultExpiresIn = 600,
	}: {
		endpointUri: string;
		password?: string;
		defaultExpiresIn?: number;
	}) {
		this.redis = createClient({
			url: endpointUri,
			password,
			socket: {
				reconnectStrategy: (retries) => {
					const jitter = Math.floor(Math.random() * 200);
					const delay = Math.min(2 ** retries * 50, 2000);
					return delay + jitter;
				},
			},
		}) as RedisClientType;
		this.defaultExpiresIn = defaultExpiresIn;
	}

	async initialize(): Promise<void> {
		await this.redis.connect();
	}

	async createCode({
		code_challenge,
		code_challenge_method,
		expiresIn = this.defaultExpiresIn,
	}: {
		code_challenge?: string;
		code_challenge_method?: string;
		expiresIn?: number;
	}): Promise<Code> {
		const code = crypto.randomBytes(32).toString("base64url");

		await this.redis.set(
			KEY_PREFIX + code,
			JSON.stringify({ code_challenge, code_challenge_method }),
			{ EX: expiresIn },
		);

		return { code, code_challenge, code_challenge_method, expiresIn };
	}

	async getByCode(code: string): Promise<Code | null> {
		const value = await this.redis.get(KEY_PREFIX + code);
		if (!value) return null;
		try {
			return { ...JSON.parse(value), code } as Code;
		} catch (err) {
			console.error(`RedisCodeRepository: corrupted data for code ${code}`, err);
			return null;
		}
	}

	async removeByCode(code: string): Promise<void> {
		await this.redis.del(KEY_PREFIX + code);
	}
}
