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
import type { CodeRepository, CreateCodeInput } from "./CodeRepository.mjs";
import type { Code } from "./types.mjs";

interface StoredCode extends Code {
	expiresAt: number;
}

/**
 * A code's lifetime, in seconds, is a positive finite number, or the code is
 * refused. NaN is never `>= now`, so a code minted with it was redeemable for
 * ever and outlived every sweep; ±Infinity is no lifetime; zero or less is a
 * code dead on arrival, which the Redis repository cannot store at all.
 */
const requireLifetime = (seconds: number, what: string): number => {
	if (!Number.isFinite(seconds) || seconds <= 0) {
		throw new RangeError(
			`InMemoryCodeRepository: ${what} must be a positive finite number of seconds (got ${String(seconds)})`,
		);
	}
	return seconds;
};

export class InMemoryCodeRepository implements CodeRepository {
	private codes = new Map<string, StoredCode>();
	private readonly defaultExpiresIn: number;
	private cleanupInterval: ReturnType<typeof setInterval>;

	constructor(options?: { defaultExpiresIn?: number }) {
		// Before the timer, so a refused default leaves nothing running.
		this.defaultExpiresIn = requireLifetime(options?.defaultExpiresIn ?? 600, "defaultExpiresIn");

		this.cleanupInterval = setInterval(() => {
			const now = Date.now();
			for (const [key, stored] of this.codes) {
				if (now >= stored.expiresAt) this.codes.delete(key);
			}
		}, 10_000);
	}

	async createCode(params: CreateCodeInput): Promise<Code> {
		const expiresIn = requireLifetime(params.expiresIn ?? this.defaultExpiresIn, "expiresIn");
		const code = crypto.randomBytes(32).toString("base64url");
		const stored: StoredCode = {
			code,
			client_id: params.client_id,
			redirect_uri: params.redirect_uri,
			code_challenge: params.code_challenge,
			code_challenge_method: params.code_challenge_method,
			expiresIn,
			expiresAt: Date.now() + expiresIn * 1000,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
			nonce: params.nonce,
			sid: params.sid,
			acr: params.acr,
		};
		this.codes.set(code, stored);
		return {
			code,
			client_id: params.client_id,
			redirect_uri: params.redirect_uri,
			code_challenge: params.code_challenge,
			code_challenge_method: params.code_challenge_method,
			expiresIn,
			grantedScope: params.grantedScope,
			grantedAudience: params.grantedAudience,
			nonce: params.nonce,
			sid: params.sid,
			acr: params.acr,
		};
	}

	async findByCode(code: string): Promise<Code | null> {
		const stored = this.codes.get(code);
		if (!stored) return null;
		if (Date.now() >= stored.expiresAt) {
			this.codes.delete(code);
			return null;
		}
		return {
			code: stored.code,
			client_id: stored.client_id,
			redirect_uri: stored.redirect_uri,
			code_challenge: stored.code_challenge,
			code_challenge_method: stored.code_challenge_method,
			expiresIn: stored.expiresIn,
			grantedScope: stored.grantedScope,
			grantedAudience: stored.grantedAudience,
			nonce: stored.nonce,
			sid: stored.sid,
			acr: stored.acr,
		};
	}

	async consumeByCode(code: string): Promise<Code | null> {
		const stored = this.codes.get(code);
		if (!stored) return null;
		this.codes.delete(code);
		if (Date.now() >= stored.expiresAt) return null;
		return {
			code: stored.code,
			client_id: stored.client_id,
			redirect_uri: stored.redirect_uri,
			code_challenge: stored.code_challenge,
			code_challenge_method: stored.code_challenge_method,
			expiresIn: stored.expiresIn,
			grantedScope: stored.grantedScope,
			grantedAudience: stored.grantedAudience,
			nonce: stored.nonce,
			sid: stored.sid,
			acr: stored.acr,
		};
	}

	async removeByCode(code: string): Promise<void> {
		this.codes.delete(code);
	}

	dispose(): void {
		clearInterval(this.cleanupInterval);
	}
}
