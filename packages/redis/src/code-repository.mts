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
	type CodeAuthentication,
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
 * `CodeData.authentication` as the payload stores it: `mfaAt` as epoch
 * milliseconds, as the session envelope stores it, and both keys always
 * written — `null` where the snapshot holds `undefined`, which JSON drops —
 * so an envelope that leaves one out reads as none.
 */
interface StoredCodeAuthentication {
	readonly primary: string | null;
	readonly mfaAtMs: number | null;
}

/**
 * Shape persisted as JSON in Redis for each authorization code: the record
 * but the code, which is the key, with `authentication` in its stored form.
 *
 * Derived from `Code` rather than declared again, with every key required,
 * so a field added to `CodeData` but not written in `createCode` or copied
 * back in `parseCodeValue` fails to compile instead of being dropped
 * silently. `JSON.stringify` leaves out a key holding `undefined`.
 */
type StoredCodePayload = Omit<Code, "code" | "authentication"> & {
	readonly authentication: StoredCodeAuthentication | undefined;
};

/** The epoch milliseconds a `Date` round-trips: a safe whole number in the `Date` range, never before 1970. */
const isStoredInstant = (ms: unknown): ms is number =>
	typeof ms === "number" && Number.isSafeInteger(ms) && ms >= 0 && ms <= 8_640_000_000_000_000;

/**
 * Whether `value` is a plain object (its prototype `Object.prototype` or
 * `null`) with `primary` and the instant's key as its own keys: the rule core
 * reads a code's `authentication` by.
 */
const isSnapshot = (value: unknown, instantKey: "mfaAt" | "mfaAtMs"): value is object => {
	if (typeof value !== "object" || value === null) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return (
		(prototype === Object.prototype || prototype === null) &&
		Object.hasOwn(value, "primary") &&
		Object.hasOwn(value, instantKey)
	);
};

/**
 * `authentication` in its stored form, or none for one not in a shape a code
 * records: not a plain object with `primary` and `mfaAt` its own keys; a
 * `primary` that is neither `undefined` nor a non-empty string; an `mfaAt`
 * that is neither `undefined` nor a `Date` that round-trips.
 */
const storedAuthentication = (
	authentication: CodeAuthentication | undefined,
): StoredCodeAuthentication | undefined => {
	if (!isSnapshot(authentication, "mfaAt")) return undefined;
	const { primary, mfaAt } = authentication as Partial<Record<keyof CodeAuthentication, unknown>>;
	if (primary !== undefined && (typeof primary !== "string" || primary.length === 0)) {
		return undefined;
	}
	const mfaAtMs = mfaAt instanceof Date ? mfaAt.getTime() : undefined;
	if (mfaAt !== undefined && !isStoredInstant(mfaAtMs)) return undefined;
	return { primary: primary ?? null, mfaAtMs: mfaAtMs ?? null };
};

/**
 * A stored `authentication` read back, or `undefined` for none and for one
 * not in the stored shape: not a plain object with both keys its own; a `primary`
 * that is neither `null` nor a non-empty string; an `mfaAtMs` that is
 * neither `null` nor an instant a `Date` round-trips. Mapped at the boundary;
 * the exchange decides what a code without one is.
 */
const readStoredAuthentication = (stored: unknown): CodeAuthentication | undefined => {
	if (!isSnapshot(stored, "mfaAtMs")) return undefined;
	const { primary, mfaAtMs } = stored as Record<keyof StoredCodeAuthentication, unknown>;
	if (primary !== null && (typeof primary !== "string" || primary.length === 0)) return undefined;
	if (mfaAtMs !== null && !isStoredInstant(mfaAtMs)) return undefined;
	return {
		primary: primary === null ? undefined : primary,
		mfaAt: mfaAtMs === null ? undefined : new Date(mfaAtMs),
	};
};

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
		// Direct-construction guard: the module's section schema already rejects
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
		authentication,
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
		const stored = storedAuthentication(authentication);
		const payload: StoredCodePayload = {
			client_id,
			redirect_uri,
			code_challenge,
			code_challenge_method,
			nonce,
			sid,
			acr,
			amr: amr ? [...amr] : undefined,
			authentication: stored,
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
		// What the payload reads back as, so the answer is what a read answers.
		return { code, ...payload, authentication: readStoredAuthentication(stored) };
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
				authentication: readStoredAuthentication(p.authentication),
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
