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
	type Logger,
	type PathResolver,
} from "@o3co/auth-provider-core";

const KEY_PREFIX = "oauth:code:";

// Minimal interface for the redis client methods we use.
// Avoids importing the full "redis" types at the module level.
interface RedisClient {
	connect(): Promise<void>;
	get(key: string): Promise<string | null>;
	set(key: string, value: string, options?: { EX?: number }): Promise<unknown>;
	getDel(key: string): Promise<string | null>;
	del(key: string): Promise<number>;
}

// Quit shape lives on the concrete node-redis client returned by `createClient`
// but is intentionally NOT part of the public `RedisClient` interface (which
// stays minimal per `feedback_no_vendor_in_interface`). The cast in
// `[Symbol.asyncDispose]` reaches the runtime quit() method via the private
// `redis` field — no interface widening needed.
interface RedisClientWithQuit extends RedisClient {
	quit(): Promise<void>;
}

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

export class RedisCodeRepository implements CodeRepository {
	private redis: RedisClient;
	private defaultExpiresIn: number;
	private logger: Logger;
	// D-5: idempotence flag — `[Symbol.asyncDispose]` fallback in the boot
	// planner AND the LifecycleRegistrar drain both target the same instance,
	// so `dispose()` may be called twice. The second call must be a no-op
	// instead of issuing a second `quit()` against a closed client (which
	// throws `ClientClosedError` on node-redis v5).
	private disposed = false;

	constructor(redis: RedisClient, defaultExpiresIn = 600, logger: Logger = consoleLogger) {
		this.redis = redis;
		this.defaultExpiresIn = defaultExpiresIn;
		this.logger = logger;
	}

	static async create(
		config: Record<string, unknown>,
		pathResolver?: PathResolver,
		logger: Logger = consoleLogger,
	): Promise<RedisCodeRepository> {
		if (typeof config.endpointUri !== "string") {
			throw new Error('RedisCodeRepository requires "endpointUri" in config');
		}

		const { createClient } = pathResolver
			? ((await import(pathResolver("redis"))) as typeof import("redis"))
			: await import("redis");

		const redis = createClient({
			url: config.endpointUri,
			password: typeof config.password === "string" ? config.password : undefined,
			socket: {
				reconnectStrategy: (retries: number) => {
					const jitter = Math.floor(Math.random() * 200);
					const delay = Math.min(2 ** retries * 50, 2000);
					return delay + jitter;
				},
			},
		});
		const defaultExpiresIn =
			typeof config.defaultExpiresIn === "number" ? config.defaultExpiresIn : undefined;
		const repo = new RedisCodeRepository(redis as unknown as RedisClient, defaultExpiresIn, logger);
		await repo.initialize();
		return repo;
	}

	async initialize(): Promise<void> {
		await this.redis.connect();
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
		await this.redis.set(KEY_PREFIX + code, JSON.stringify(payload), { EX: expiresIn });
		return { code, ...payload };
	}

	async getByCode(code: string): Promise<Code | null> {
		const value = await this.redis.get(KEY_PREFIX + code);
		return this.parseCodeValue(code, value);
	}

	async consumeByCode(code: string): Promise<Code | null> {
		const value = await this.redis.getDel(KEY_PREFIX + code);
		return this.parseCodeValue(code, value);
	}

	async removeByCode(code: string): Promise<void> {
		await this.redis.del(KEY_PREFIX + code);
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
			return {
				code,
				client_id: p.client_id,
				redirect_uri: p.redirect_uri,
				code_challenge: p.code_challenge,
				code_challenge_method: p.code_challenge_method,
				nonce: p.nonce,
				sid: p.sid,
				expiresIn: p.expiresIn,
				grantedScope: p.grantedScope,
				grantedAudience: p.grantedAudience,
			};
		} catch (err) {
			const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
			this.logger.error({ err, codeHash }, "RedisCodeRepository: corrupted data for code");
			return null;
		}
	}

	/**
	 * Disconnect the underlying Redis client (D-5 / OR-2). The
	 * `redisCodeRepositoryBuilder` registers this with `BuilderContext.lifecycle`
	 * so `AppHandle.dispose()` drains the connection automatically. The cast
	 * reaches the runtime `quit()` method on the concrete node-redis client
	 * without widening the minimal `RedisClient` interface (per
	 * `feedback_no_vendor_in_interface`).
	 */
	async [Symbol.asyncDispose](): Promise<void> {
		if (this.disposed) return;
		this.disposed = true;
		// Runtime guard: the public `RedisClient` interface does NOT declare
		// `quit()` (kept minimal per `feedback_no_vendor_in_interface`), but
		// the concrete node-redis client returned by `createClient()` always
		// provides it. Custom `RedisClient` implementations passed via the
		// public constructor MUST also implement `quit()` for D-5 lifecycle
		// integration to work — fail loudly with a clear message instead of
		// throwing an opaque `client.quit is not a function` TypeError.
		const client = this.redis as Partial<RedisClientWithQuit>;
		if (typeof client.quit !== "function") {
			throw new Error(
				"RedisCodeRepository.dispose(): underlying redis client does not implement quit(). " +
					"Custom RedisClient implementations passed to the constructor must provide a `quit(): Promise<void>` " +
					"method for D-5 lifecycle integration.",
			);
		}
		await client.quit();
	}

	/**
	 * Alias for `[Symbol.asyncDispose]` for call sites that cannot use
	 * `await using`. Returns the same Promise.
	 */
	dispose(): Promise<void> {
		return this[Symbol.asyncDispose]();
	}
}

/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisCodeRepositoryBuilder);
 *
 * `config` shape: `{ endpointUri: string; password?: string; defaultExpiresIn?: number }`.
 *
 * The repository is constructed and connected lazily on first call to
 * `factory.create(...)`. The redis client lifetime is owned by the repo
 * instance: D-5 wired the builder to `ctx.lifecycle?.register(...)` so
 * `AppHandle.dispose()` drains `repo.dispose()` (which calls `quit()` on the
 * underlying client) automatically. Call sites that cannot use `await using`
 * may invoke `repo.dispose()` directly.
 *
 * Module pattern wrapper for `codeRepository` slot is intentionally NOT
 * provided in v0.5.0 — see Phase 10 plan §1 / Q4 (deferred to a separate
 * "legacy-slot module-parity" PR).
 */
export const redisCodeRepositoryBuilder: AdapterBuilder<CodeRepository> = async (config, ctx) => {
	if (typeof config.endpointUri !== "string") {
		throw new Error('RedisCodeRepository requires "endpointUri" in config');
	}
	const repo = await RedisCodeRepository.create(config);
	ctx.lifecycle?.register(async () => {
		await repo.dispose();
	});
	return repo;
};
