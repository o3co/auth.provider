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
import { RedisClient } from "./base/RedisClient.mjs";

export interface Code {
	code: string;
	code_challenge?: string;
	code_challenge_method?: string;
	expiresIn?: number;
}

export class CodeClient extends RedisClient {
	private readonly defaultExpiresIn: number;

	constructor({
		endpointUri,
		password,
		defaultExpiresIn = 600, // 10 minutes
	}: { endpointUri: string; password?: string; defaultExpiresIn?: number }) {
		super({ endpointUri, password });
		this.defaultExpiresIn = defaultExpiresIn;
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

		await this.setByCode(code, { code_challenge, code_challenge_method }, { expiresIn });

		return {
			code,
			code_challenge,
			code_challenge_method,
			expiresIn,
		};
	}

	async getByCode(code: string): Promise<Code | null> {
		const value = await this.redis.get(code);
		if (!value) return null;
		return { ...JSON.parse(value), code } as Code;
	}

	async setByCode(
		code: string,
		{
			code_challenge,
			code_challenge_method,
		}: {
			code_challenge?: string;
			code_challenge_method?: string;
		},
		{ expiresIn }: { expiresIn: number | undefined } = {
			expiresIn: undefined,
		},
	): Promise<void> {
		await this.redis.set(
			code,
			JSON.stringify({
				code_challenge,
				code_challenge_method,
			}),
			{ EX: expiresIn ?? undefined },
		);
	}
}
