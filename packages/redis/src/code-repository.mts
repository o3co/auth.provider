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
	type CreateCodeInput,
	consoleLogger,
	defineModule,
	isStorableLifetime,
	type Logger,
	loggableError,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { CodeRepositoryClient } from "./clients.mjs";

const DEFAULT_KEY_PREFIX = "oauth:code:";
const DEFAULT_EXPIRES_IN_SECONDS = 600;

/**
 * Shape persisted as JSON in Redis for each authorization code (D-1): the
 * record but the code, which is the key.
 *
 * Derived from `Code` rather than declared again (#626). Declared by hand, a
 * field added to `CodeData` had to be destructured in `createCode`, added
 * here and copied back in `parseCodeValue`, and missing any one of the three
 * dropped it without an error — the IH-2 / TS-1 / TD-1 production bug v0.5.1
 * closed. Every key is required now, so each of those steps fails to compile
 * instead. `JSON.stringify` leaves out a key holding `undefined`, so what is
 * stored is byte-for-byte what it was.
 */
type StoredCodePayload = Omit<Code, "code">;

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
		// Direct-construction guard: the module configSchema already rejects
		// non-positive integers, but consumers calling
		// `new RedisCodeRepository(client, { defaultExpiresIn: 0 })`
		// directly would otherwise sail past validation and hit Redis with
		// a bad PX argument. Reject at construction time with a clear
		// message so the failure mode is the same regardless of wiring path.
		// Per Copilot review on PR #122.
		const expiresIn = opts.defaultExpiresIn;
		if (expiresIn !== undefined) {
			if (!Number.isInteger(expiresIn) || !isStorableLifetime(expiresIn * 1000)) {
				throw new RangeError(
					`RedisCodeRepository: defaultExpiresIn must be a positive integer (seconds), got ${expiresIn}`,
				);
			}
		}
		this.defaultExpiresIn = expiresIn ?? DEFAULT_EXPIRES_IN_SECONDS;
		this.logger = opts.logger ?? consoleLogger;
	}

	async createCode({
		client_id,
		redirect_uri,
		code_challenge,
		code_challenge_method,
		nonce,
		sid,
		acr,
		expiresIn = this.defaultExpiresIn,
		grantedScope,
		grantedAudience,
	}: CreateCodeInput): Promise<Code> {
		// A per-call lifetime is the caller's number, not the validated default:
		// NaN or ±Infinity would be `PX NaN`, zero or less a PX Redis refuses,
		// and each surfaced as a failed /authorize rather than as the caller's
		// fault it is.
		if (!isStorableLifetime(expiresIn * 1000)) {
			throw new RangeError(
				`RedisCodeRepository.createCode: expiresIn must be a positive finite number of seconds that ends within the Date range (got ${String(expiresIn)})`,
			);
		}
		const code = crypto.randomBytes(32).toString("base64url");
		const payload: StoredCodePayload = {
			client_id,
			redirect_uri,
			code_challenge,
			code_challenge_method,
			nonce,
			sid,
			acr,
			expiresIn,
			grantedScope: grantedScope ? [...grantedScope] : undefined,
			grantedAudience: grantedAudience ? [...grantedAudience] : undefined,
		};
		// PX expiry is in milliseconds; HOCON expiresIn is in seconds. `PX` takes
		// whole milliseconds, so a fractional lifetime is rounded up: the code
		// lives at least as long as it was given, never less.
		await this.client.set(
			this.keyPrefix + code,
			JSON.stringify(payload),
			"PX",
			Math.ceil(expiresIn * 1000),
		);
		return { code, ...payload };
	}

	async findByCode(code: string): Promise<Code | null> {
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
			// external writer touches this key namespace. `Partial`, because the
			// JSON has no key for a field that held `undefined` (#626): a spread
			// of it into the record below would leave the key out, and fails to
			// compile, where naming each field does not.
			const p = JSON.parse(value) as Partial<StoredCodePayload>;
			// Pre-v0.5.1 codes lack `client_id` / `redirect_uri` (the IH-2 / TS-1
			// production drop bug). Treat them as corrupt — the strict identity
			// gates in /token would reject them anyway, but failing here keeps the
			// failure mode aligned with the corrupted-JSON branch and prevents
			// `client_id: undefined` from leaking into downstream gates as a
			// runtime null.
			if (typeof p.client_id !== "string" || typeof p.redirect_uri !== "string") {
				const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
				this.logger.error(
					{ codeHash, reason: "identity_fields_missing" },
					"authorization_code_corrupt_record",
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
				acr: p.acr,
				expiresIn: p.expiresIn,
				grantedScope,
				grantedAudience,
			};
		} catch (err) {
			// The projection, never the error: a SyntaxError's message quotes
			// the stored record around the point it failed.
			const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
			this.logger.error(
				{ codeHash, reason: "json_parse", err: loggableError(err) },
				"authorization_code_corrupt_record",
			);
			return null;
		}
	}
}

/**
 * @deprecated since v0.5.1 (OR-9). Use `redisCodeRepositoryModule` (DI module
 * pattern) instead. The builder now expects `{ client, keyPrefix?,
 * defaultExpiresIn? }` (the same shape the module passes internally) — the
 * pre-v0.5.1 `{ endpointUri }` shape is no longer supported. See CHANGELOG
 * for the removal version.
 *
 * Migration: stop calling `factory.register("redis", redisCodeRepositoryBuilder)`;
 * instead include `redisCodeRepositoryModule` in the manifest and provide the
 * `codeRepositoryClient` slot from `makeIoredisClients()`.
 *
 * Each call logs `adapter_builder_deprecated` (warn, `builder`,
 * `replacement`) on the factory context's logger, or on `consoleLogger`.
 */
export const redisCodeRepositoryBuilder: AdapterBuilder<CodeRepository> = (config, ctx) => {
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
	// One object-first line on the logger the factory's context carries; the
	// builder is called outside the boot planner too, where there is none.
	(ctx?.logger ?? consoleLogger).warn(
		{ builder: "redisCodeRepositoryBuilder", replacement: "redisCodeRepositoryModule" },
		"adapter_builder_deprecated",
	);
	return new RedisCodeRepository(c.client, {
		keyPrefix: c.keyPrefix,
		defaultExpiresIn: c.defaultExpiresIn,
		...(ctx?.logger !== undefined ? { logger: ctx.logger } : {}),
	});
};

/**
 * `defineModule` manifest for the Redis CodeRepository (OR-9 / Wave 5d).
 *
 * Static composition path. `redisCodeRepositoryBuilder` is still exported
 * but deprecated — operators wiring redis codes should switch to this
 * module + provide `codeRepositoryClient` from `makeIoredisClients()` —
 * see CHANGELOG for the removal version.
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
	// Where a stored record that cannot be read is reported
	// (`authorization_code_corrupt_record`); consoleLogger when empty.
	optional: ["logger"] as const,
	configSchema: z.object({
		redisCodeRepository: z
			.object({
				keyPrefix: z.string().optional(),
				// `defaultExpiresIn` controls the Redis PX TTL (seconds) for
				// authorization codes. Constrained to a positive integer so a
				// bad env-var override (`CLIENT_CODE_DEFAULT_EXPIRES_IN=0`,
				// `="-1"`, or `="abc"`) fails Zod validation at boot rather
				// than producing a non-positive PX argument that Redis rejects
				// at first /authorize call. Per Copilot review on PR #122.
				defaultExpiresIn: z.coerce.number().int().positive().optional(),
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
				...(deps.logger !== undefined ? { logger: deps.logger } : {}),
			});
		},
	},
});
