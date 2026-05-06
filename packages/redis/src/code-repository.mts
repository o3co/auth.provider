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
import {
	type AdapterBuilder,
	type Code,
	type CodeRepository,
	consoleLogger,
	defineModule,
	type Logger,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { CodeRepositoryClient } from "./clients.mjs";

const DEFAULT_KEY_PREFIX = "oauth:code:";
const DEFAULT_EXPIRES_IN_SECONDS = 600;

/**
 * Shape persisted as JSON in Redis for each authorization code (D-1).
 *
 * Mirrors `Parameters<CodeRepository["createCode"]>[0]` plus a private
 * `expiresIn` echo so reads can reconstruct the original record. The
 * destructure of `createCode` MUST stay in sync with this shape — adding
 * a field to `CodeData` requires destructuring it AND extending this
 * interface, otherwise the Redis path silently drops it (which was the
 * IH-2 / TS-1 / TD-1 production bug v0.5.1 closes).
 */
interface StoredCodePayload {
	client_id: string;
	redirect_uri: string;
	code_challenge?: string;
	code_challenge_method?: string;
	nonce?: string;
	sid?: string;
	expiresIn?: number;
	grantedScope?: string[];
	grantedAudience?: string[];
}

/**
 * Options accepted by the public `RedisCodeRepository` constructor.
 *
 * Per OR-9 (Wave 5d): the connection lifecycle is owned by the consumer
 * (composition root); the repository only consumes the typed
 * `CodeRepositoryClient` wrapper. No internal client construction, no
 * `quit()` call, no `[Symbol.asyncDispose]`.
 */
export interface RedisCodeRepositoryOptions {
	readonly keyPrefix?: string;
	readonly defaultExpiresIn?: number;
	readonly logger?: Logger;
}

export class RedisCodeRepository implements CodeRepository {
	private readonly client: CodeRepositoryClient;
	private readonly keyPrefix: string;
	private readonly defaultExpiresIn: number;
	private readonly logger: Logger;

	constructor(client: CodeRepositoryClient, opts: RedisCodeRepositoryOptions = {}) {
		this.client = client;
		this.keyPrefix = opts.keyPrefix ?? DEFAULT_KEY_PREFIX;
		this.defaultExpiresIn = opts.defaultExpiresIn ?? DEFAULT_EXPIRES_IN_SECONDS;
		this.logger = opts.logger ?? consoleLogger;
	}

	async createCode({
		client_id,
		redirect_uri,
		code_challenge,
		code_challenge_method,
		nonce,
		sid,
		expiresIn = this.defaultExpiresIn,
		grantedScope,
		grantedAudience,
	}: Parameters<CodeRepository["createCode"]>[0]): Promise<Code> {
		const code = crypto.randomBytes(32).toString("base64url");
		const payload: StoredCodePayload = {
			client_id,
			redirect_uri,
			code_challenge,
			code_challenge_method,
			nonce,
			sid,
			expiresIn,
			grantedScope: grantedScope ? [...grantedScope] : undefined,
			grantedAudience: grantedAudience ? [...grantedAudience] : undefined,
		};
		// PX expiry is in milliseconds; HOCON expiresIn is in seconds.
		await this.client.set(this.keyPrefix + code, JSON.stringify(payload), "PX", expiresIn * 1000);
		return { code, ...payload };
	}

	async getByCode(code: string): Promise<Code | null> {
		const value = await this.client.get(this.keyPrefix + code);
		return this.parseCodeValue(code, value);
	}

	async consumeByCode(code: string): Promise<Code | null> {
		const value = await this.client.getDel(this.keyPrefix + code);
		return this.parseCodeValue(code, value);
	}

	async removeByCode(code: string): Promise<void> {
		await this.client.del(this.keyPrefix + code);
	}

	private parseCodeValue(code: string, value: string | null): Code | null {
		if (!value) return null;
		try {
			// The cast trusts the stored format — `StoredCodePayload` is a private
			// internal type that exactly mirrors what `createCode` serializes; no
			// external writer touches this key namespace.
			const p = JSON.parse(value) as StoredCodePayload;
			// Pre-v0.5.1 codes lack `client_id` / `redirect_uri` (the IH-2 / TS-1
			// production drop bug). Treat them as corrupt — the strict identity
			// gates in /token would reject them anyway, but failing here keeps the
			// failure mode aligned with the corrupted-JSON branch and prevents
			// `client_id: undefined` from leaking into downstream gates as a
			// runtime null.
			if (typeof p.client_id !== "string" || typeof p.redirect_uri !== "string") {
				const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
				this.logger.error(
					{ codeHash },
					"RedisCodeRepository: legacy/corrupted code record missing required identity fields",
				);
				return null;
			}
			// Defensive type guards on optional array fields. The `as
			// StoredCodePayload` cast trusts JSON shape; without these, a
			// corrupted record with `grantedScope: "not-an-array"` would
			// propagate a non-array up to downstream gates (scope filter / aud
			// narrowing) that assume `readonly string[]`. Drop on shape mismatch
			// rather than throw — the strict `/token` gates downstream will
			// then reject naturally on the missing claim.
			const grantedScope = Array.isArray(p.grantedScope) ? p.grantedScope : undefined;
			const grantedAudience = Array.isArray(p.grantedAudience) ? p.grantedAudience : undefined;
			return {
				code,
				client_id: p.client_id,
				redirect_uri: p.redirect_uri,
				code_challenge: p.code_challenge,
				code_challenge_method: p.code_challenge_method,
				nonce: p.nonce,
				sid: p.sid,
				expiresIn: p.expiresIn,
				grantedScope,
				grantedAudience,
			};
		} catch (err) {
			const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
			this.logger.error({ err, codeHash }, "RedisCodeRepository: corrupted data for code");
			return null;
		}
	}
}

/**
 * @deprecated since v0.5.1 (OR-9). Use `redisCodeRepositoryModule` (DI module
 * pattern) instead. The builder now expects `{ client, keyPrefix?,
 * defaultExpiresIn? }` (the same shape the module passes internally) — the
 * pre-v0.5.1 `{ endpointUri }` shape is no longer supported. Removed in v0.6.
 *
 * Migration: stop calling `factory.register("redis", redisCodeRepositoryBuilder)`;
 * instead include `redisCodeRepositoryModule` in the manifest and provide the
 * `codeRepositoryClient` slot from `makeIoredisClients()`.
 */
export const redisCodeRepositoryBuilder: AdapterBuilder<CodeRepository> = (config, _ctx) => {
	const c = config as {
		client?: CodeRepositoryClient;
		keyPrefix?: string;
		defaultExpiresIn?: number;
	};
	if (!c.client) {
		throw new Error(
			"redisCodeRepositoryBuilder: 'client' option is required (legacy { endpointUri } " +
				"shape removed in v0.5.1). Use redisCodeRepositoryModule with a codeRepositoryClient " +
				"slot from makeIoredisClients() instead.",
		);
	}
	consoleLogger.warn(
		"redisCodeRepositoryBuilder is deprecated; use redisCodeRepositoryModule (will be removed in v0.6).",
	);
	return new RedisCodeRepository(c.client, {
		keyPrefix: c.keyPrefix,
		defaultExpiresIn: c.defaultExpiresIn,
	});
};

/**
 * `defineModule` manifest for the Redis CodeRepository (OR-9 / Wave 5d).
 *
 * Static composition path. The legacy `redisCodeRepositoryBuilder` still
 * exists for one release cycle but is deprecated — operators wiring redis
 * codes should switch to this module + provide `codeRepositoryClient` from
 * `makeIoredisClients()`.
 *
 * configSchema: top-level key `redisCodeRepository` (module-namespaced per
 * master roadmap §3.5). No `.default()` per ADR — defaults live in
 * `application.conf`. The constructor falls back to its built-in defaults
 * (`oauth:code:` / 600s) when both HOCON and operator overrides omit a
 * field; mirrors the `?? DEFAULT_*` pattern in the constructor body.
 */
export const redisCodeRepositoryModule = defineModule({
	name: "redis-code-repository",
	requires: ["codeRepositoryClient", "config"] as const,
	configSchema: z.object({
		redisCodeRepository: z
			.object({
				keyPrefix: z.string().optional(),
				defaultExpiresIn: z.coerce.number().optional(),
			})
			.optional(),
	}),
	provides: {
		codeRepository: (deps) => {
			const cfg = (
				deps.config as {
					redisCodeRepository?: { keyPrefix?: string; defaultExpiresIn?: number };
				}
			).redisCodeRepository;
			return new RedisCodeRepository(deps.codeRepositoryClient, {
				keyPrefix: cfg?.keyPrefix,
				defaultExpiresIn: cfg?.defaultExpiresIn,
			});
		},
	},
});
