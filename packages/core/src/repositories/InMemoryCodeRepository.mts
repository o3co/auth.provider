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
import type { CodeRepository } from "./CodeRepository.mjs";
import type { Code } from "./types.mjs";

interface StoredCode extends Code {
	expiresAt: number;
	redirect_uri?: string;
	grantedScope?: readonly string[];
	grantedAudience?: readonly string[];
}

export class InMemoryCodeRepository implements CodeRepository {
	private codes = new Map<string, StoredCode>();
	private readonly defaultExpiresIn: number;
	private cleanupInterval: ReturnType<typeof setInterval>;

	constructor(options?: { defaultExpiresIn?: number }) {
		this.defaultExpiresIn = options?.defaultExpiresIn ?? 600;

		this.cleanupInterval = setInterval(() => {
			const now = Date.now();
			for (const [key, stored] of this.codes) {
				if (now >= stored.expiresAt) this.codes.delete(key);
			}
		}, 10_000);
	}

	async createCode(params: {
		code_challenge?: string;
		code_challenge_method?: string;
		redirect_uri?: string;
		expiresIn?: number;
		grantedScope?: readonly string[];
		grantedAudience?: readonly string[];
	}): Promise<Code> {
		const code = crypto.randomBytes(32).toString("base64url");
		const expiresIn = params.expiresIn ?? this.defaultExpiresIn;
		const stored: StoredCode = {
			code,
			code_challenge: params.code_challenge,
			code_challenge_method: params.code_challenge_method,
			redirect_uri: params.redirect_uri,
			expiresIn,
			expiresAt: Date.now() + expiresIn * 1000,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
		};
		this.codes.set(code, stored);
		return {
			code,
			code_challenge: params.code_challenge,
			code_challenge_method: params.code_challenge_method,
			redirect_uri: params.redirect_uri,
			expiresIn,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
		};
	}

	async getByCode(code: string): Promise<Code | null> {
		const stored = this.codes.get(code);
		if (!stored) return null;
		if (Date.now() >= stored.expiresAt) {
			this.codes.delete(code);
			return null;
		}
		return {
			code: stored.code,
			code_challenge: stored.code_challenge,
			code_challenge_method: stored.code_challenge_method,
			redirect_uri: stored.redirect_uri,
			expiresIn: stored.expiresIn,
			grantedScope: stored.grantedScope,
			grantedAudience: stored.grantedAudience,
		};
	}

	async consumeByCode(code: string): Promise<Code | null> {
		const stored = this.codes.get(code);
		if (!stored) return null;
		this.codes.delete(code);
		if (Date.now() >= stored.expiresAt) return null;
		return {
			code: stored.code,
			code_challenge: stored.code_challenge,
			code_challenge_method: stored.code_challenge_method,
			redirect_uri: stored.redirect_uri,
			expiresIn: stored.expiresIn,
			grantedScope: stored.grantedScope,
			grantedAudience: stored.grantedAudience,
		};
	}

	async removeByCode(code: string): Promise<void> {
		this.codes.delete(code);
	}

	dispose(): void {
		clearInterval(this.cleanupInterval);
	}
}
