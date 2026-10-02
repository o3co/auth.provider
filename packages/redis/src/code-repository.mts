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
	wellFormedAmr,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { CodeRepositoryClient } from "./clients.mjs";

const DEFAULT_KEY_PREFIX = "oauth:code:";
const DEFAULT_EXPIRES_IN_SECONDS = 600;

/**
 * Shape persisted as JSON in Redis for each authorization code: the record
 * but the code, which is the key.
 *
 * Derived from `Code` rather than declared again, with every key required,
 * so a field added to `CodeData` but not written in `createCode` or copied
 * back in `parseCodeValue` fails to compile instead of being dropped
 * silently. `JSON.stringify` leaves out a key holding `undefined`.
 */
type StoredCodePayload = Omit<Code, "code">;

/**
 * Options accepted by the public `RedisCodeRepository` constructor.
 *
 * The connection lifecycle is owned by the consumer
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
		// non-positive integers, but a direct
		// `new RedisCodeRepository(client, { defaultExpiresIn: 0 })` would
		// otherwise reach Redis with a bad PX argument. Rejected here so the
		// failure is the same on either wiring path.
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
		amr,
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
			amr: amr ? [...amr] : undefined,
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
			// JSON has no key for a field that held `undefined`: a spread
			// of it into the record below would leave the key out, and fails to
			// compile, where naming each field does not.
			const p = JSON.parse(value) as Partial<StoredCodePayload>;
			// A record without `client_id` / `redirect_uri` is corrupt — the
			// strict identity gates in /token would reject it anyway, but failing
			// here aligns with the corrupted-JSON branch and keeps
			// `client_id: undefined` out of downstream gates.
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
			// Mapped at the boundary: a list of non-empty strings, else none.
			const amr = wellFormedAmr(p.amr);
			return {
				code,
				client_id: p.client_id,
				redirect_uri: p.redirect_uri,
				code_challenge: p.code_challenge,
				code_challenge_method: p.code_challenge_method,
				nonce: p.nonce,
				sid: p.sid,
				acr: p.acr,
				amr,
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
 * @deprecated Use `redisCodeRepositoryModule` (DI module pattern) instead.
 * The builder expects `{ client, keyPrefix?, defaultExpiresIn? }`, the shape
 * the module passes internally. See CHANGELOG for the removal version.
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
 * The schema of `redis-code-repository {}`, the module's own section, strict:
 * the key namespace and the default lifetime in seconds, a positive whole
 * number so a bad variable fails boot rather than every Redis call. Absent,
 * the repository's own defaults apply (`oauth:code:`, 600).
 */
const redisCodeRepositorySectionSchema = z
	.object({
		keyPrefix: z.string().optional(),
		defaultExpiresIn: wholeNumberInRangeFromEnv(1).optional(),
	})
	.strict()
	.optional();

/**
 * `defineModule` manifest for the Redis CodeRepository: the static
 * composition path, which replaces the deprecated
 * `redisCodeRepositoryBuilder`. It reads its own section,
 * `redis-code-repository`, which moved from `redisCodeRepository`; the
 * `repositories.code` blocks it and the in-process repository once shared are
 * removed, and the `CLIENT_CODE_*` variables renamed after the new paths
 * (`REDIS_CODE_REPOSITORY_*`) or removed with their keys.
 */
export const redisCodeRepositoryModule = defineModule({
	name: "redis-code-repository",
	section: {
		schema: redisCodeRepositorySectionSchema,
		reference: new URL("../config/reference.conf", import.meta.url),
		relocatedFrom: {
			redisCodeRepository: "",
			"repositories.code.redis": null,
			"repositories.code.memory": null,
		},
		renamedVariables: {
			CLIENT_CODE_KEY_PREFIX: "redisCodeRepository.keyPrefix",
			CLIENT_CODE_DEFAULT_EXPIRES_IN: "redisCodeRepository.defaultExpiresIn",
			CLIENT_CODE_ENDPOINT_URI: "repositories.code.redis.endpointUri",
			CLIENT_CODE_PASSWORD: "repositories.code.redis.password",
		},
	},
	requires: ["codeRepositoryClient"] as const,
	// Where a stored record that cannot be read is reported
	// (`authorization_code_corrupt_record`); consoleLogger when empty.
	optional: ["logger"] as const,
	provides: {
		codeRepository: ({ section, codeRepositoryClient, logger }) =>
			new RedisCodeRepository(codeRepositoryClient, {
				keyPrefix: section?.keyPrefix,
				defaultExpiresIn: section?.defaultExpiresIn,
				...(logger !== undefined ? { logger } : {}),
			}),
	},
});
