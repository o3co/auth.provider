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

/**
 * The schemas of the template's own sections: its modules' — `logging`,
 * `http` (with its CORS list), `key-store`, `redis-clients`, `repositories`,
 * the in-process code repository's and `audit-sink` — and the composition
 * root's own `adapters` and `mfaMode`. Each is strict, a key it does not
 * declare refused;
 * each reads the strings an environment variable carries; none holds a
 * default, which lives in `config/reference.conf`. The rules a value is held
 * to are core's shared vocabulary (trusted-proxy entries, serialized origins,
 * key ids), applied here, never restated.
 */

import {
	checkSerializedOrigin,
	checkTrustedProxyEntry,
	coerceBooleanFromEnv,
	describeSerializedOriginRejection,
	describeTrustedProxyEntryRejection,
	isWellFormedKid,
	MAX_KID_LENGTH,
	MAX_TRUST_PROXY_HOPS,
	normalizeAllowedOrigins,
	wholeNumberFromEnv,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { mfaConfigSchema } from "@o3co/auth-provider-mfa";
import { z } from "zod";

/** `logging`: the level the process logs at. `silent` is a threshold, not a level. */
export const loggingSectionSchema = z
	.object({ level: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]) })
	.strict();

/** What the logger is built from: the `logging` module's section. */
export type LoggingSettings = z.output<typeof loggingSectionSchema>;

/**
 * A decimal, optionally signed or fractional: the variable's shapes meant as a
 * hop count, so `-1` and `1.5` fail as hop counts instead of reading as
 * one-entry address lists.
 */
const NUMERIC_STRING = /^-?[0-9]+(\.[0-9]+)?$/;

/**
 * A `trust proxy` value in one of Express's shapes: the variable's string read
 * as `true` / `false` / a hop count / a comma-separated list, a list's entries
 * trimmed. `1` and `0` are hop counts here, not booleans. An exported-but-empty
 * variable is `false`: trust nothing.
 */
const normalizeTrustProxy = (raw: unknown): unknown => {
	if (Array.isArray(raw)) {
		return raw.map((entry) => (typeof entry === "string" ? entry.trim() : entry));
	}
	if (typeof raw !== "string") return raw;
	const value = raw.trim();
	if (value === "") return false;
	const lower = value.toLowerCase();
	if (lower === "true") return true;
	if (lower === "false") return false;
	if (NUMERIC_STRING.test(value)) return Number(value);
	return value
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry !== "");
};

/**
 * `http.trustProxy`, handed to Express's `trust proxy`: `false` (trust
 * nothing), `true` (trust every hop), a hop count up to
 * `MAX_TRUST_PROXY_HOPS`, or a non-empty list of IP literals, CIDR ranges and
 * named ranges, each held to core's trusted-proxy vocabulary so a typo fails
 * at boot, naming its index, instead of never matching.
 */
const trustProxySchema = z
	.preprocess(
		normalizeTrustProxy,
		z.union([
			z.boolean(),
			z.number().int().min(0).max(MAX_TRUST_PROXY_HOPS),
			z
				.array(z.string())
				.min(
					1,
					"must list at least one address, CIDR range, or named range — use `false` to trust no forwarding hop",
				),
		]),
	)
	.superRefine((value, ctx) => {
		if (!Array.isArray(value)) return;
		value.forEach((entry, index) => {
			const rejection = checkTrustedProxyEntry(entry);
			if (rejection !== null) {
				ctx.addIssue({
					code: "custom",
					message: `http.trustProxy[${index}] ${describeTrustedProxyEntryRejection(rejection)}`,
					path: [index],
				});
			}
		});
	});

/**
 * `http.cors.allowedOrigins`: the browser origins allowed to read the token,
 * userinfo, revocation and discovery/JWKS responses; empty is CORS off. A list,
 * or the one comma-separated string `HTTP_CORS_ALLOWED_ORIGINS` carries
 * (`normalizeAllowedOrigins`, core's reading of an origin list);
 * `null` reads as no origins, any other shape is refused. Each entry must be a
 * serialized origin, matched by exact string equality: one that could never
 * match is refused, naming its index.
 */
const allowedOriginsSchema = z
	.preprocess((raw, ctx) => {
		if (raw === undefined) return raw;
		if (raw !== null && typeof raw !== "string" && !Array.isArray(raw)) {
			ctx.addIssue({
				code: "custom",
				message: `http.cors.allowedOrigins must be a list of origins, or one comma-separated string of them (HTTP_CORS_ALLOWED_ORIGINS); got ${typeof raw === "object" ? "an object" : `a ${typeof raw}`}`,
			});
			return raw;
		}
		return normalizeAllowedOrigins(raw);
	}, z.array(z.string()))
	.superRefine((value, ctx) => {
		value.forEach((entry, index) => {
			const rejection = checkSerializedOrigin(entry);
			if (rejection !== null) {
				ctx.addIssue({
					code: "custom",
					message: `http.cors.allowedOrigins[${index}] ${describeSerializedOriginRejection(rejection)}`,
					path: [index],
				});
			}
		});
	});

const PORT_RULE =
	"http.port must be a port number from 0 to 65535 in decimal digits, 0 letting the OS choose a free port (HTTP_PORT); an exported-but-empty HTTP_PORT is not one";

/**
 * `http.port`, read strictly: an empty or non-decimal value fails boot instead
 * of reading as 0, which would listen on a port the OS picks at random.
 */
const portSchema = wholeNumberFromEnv(
	z
		.number({ error: PORT_RULE })
		.int({ error: PORT_RULE })
		.min(0, { error: PORT_RULE })
		.max(65_535, { error: PORT_RULE }),
);

/**
 * `http`: the listener's port, the trusted forwarding hops, the readiness
 * deadline, and the CORS list. The deadline is bounded both ways, because
 * `setTimeout` turns 0 and anything above 2^31-1 into 1 ms: every probe would
 * time out.
 */
export const httpSectionSchema = z
	.object({
		port: portSchema,
		trustProxy: trustProxySchema,
		readinessTimeoutMs: wholeNumberInRangeFromEnv(1, 2_147_483_647),
		cors: z.object({ allowedOrigins: allowedOriginsSchema }).strict(),
	})
	.strict();

/** A key id `verifyJwt` accepts: one it would refuse would fail every token signed under it. */
const kidSchema = z.string().refine(isWellFormedKid, {
	message: `must be a key id: a string of 1 to ${MAX_KID_LENGTH} characters with no control character`,
});

/** HS256: a shared secret, rotated through `previousSecrets`. */
const hs256LocalSchema = z
	.object({
		algorithm: z.literal("HS256"),
		kid: kidSchema,
		secret: z.string().optional(),
		previousSecrets: z
			.array(z.object({ kid: kidSchema, secret: z.string(), expiresAt: z.string() }).strict())
			.optional(),
	})
	.strict();

/**
 * RS256, ES256, EdDSA: a key pair, rotated through `previousKeys`. `secret`,
 * which the reference binds for every algorithm, and `previousSecrets` are
 * accepted and left to the key store, which names what an asymmetric key
 * cannot use them for.
 */
const asymmetricLocalSchema = z
	.object({
		algorithm: z.enum(["RS256", "ES256", "EdDSA"]),
		kid: kidSchema,
		privateKey: z.string().optional(),
		privateKeyPath: z.string().optional(),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		previousKeys: z
			.array(
				z
					.object({
						kid: kidSchema,
						publicKey: z.string().optional(),
						publicKeyPath: z.string().optional(),
						expiresAt: z.string(),
					})
					.strict(),
			)
			.optional(),
		secret: z.string().optional(),
		previousSecrets: z.unknown().optional(),
	})
	.strict();

/**
 * `key-store`: which key store builds the signing key (`provider`, `local` the
 * one this template registers) and the local store's settings, shape only:
 * whether the key material is there is the key store's check, when it is
 * built.
 */
export const keyStoreSectionSchema = z
	.object({
		provider: z.string(),
		local: z.discriminatedUnion("algorithm", [hs256LocalSchema, asymmetricLocalSchema]).optional(),
	})
	.strict();

/**
 * `redis-clients`: the one Redis connection every Redis-backed store shares.
 * `assumeNoEviction` is the operator's assertion that the server runs
 * `maxmemory-policy noeviction`, read by the Redis stores' eviction gate only
 * where the server will not report its policy; the template's
 * `config/reference.conf` ships it false.
 */
export const redisClientsSectionSchema = z
	.object({
		url: z.string(),
		password: z.string().optional(),
		assumeNoEviction: coerceBooleanFromEnv,
	})
	.strict();

/**
 * `adapters`: which adapter fills each slot, the composition root's own
 * choice. `userSessionStores` switches the four user-session stores and the
 * subject-level revocation pair together; the repositories take core's
 * `static`, an alias of `yaml` with a block of its own; `mfaFactorStore` and
 * `mfaTransactionStore` are read by a composition that installs MFA;
 * `auditSink` names a sink the audit-sink module's factory registers.
 */
export const adaptersSchema = z
	.object({
		rateLimiter: z.enum(["memory", "redis"]),
		attemptCounter: z.enum(["memory", "redis"]),
		userSessionStores: z.enum(["memory", "redis"]),
		accessTokenDenylist: z.enum(["memory", "redis"]),
		replaySeenSet: z.enum(["memory", "redis"]),
		consentStore: z.enum(["none", "memory", "redis"]),
		federationTokenStore: z.enum(["memory", "redis"]),
		federationGrantStore: z.enum(["none", "memory", "redis"]),
		federationGrantIntentStore: z.enum(["none", "memory", "redis"]),
		mfaFactorStore: z.enum(["memory", "redis", "store"]),
		mfaTransactionStore: z.enum(["memory", "redis"]),
		codeRepository: z.enum(["memory", "redis"]),
		clientRepository: z.enum(["yaml", "static"]),
		userRepository: z.enum(["yaml", "static", "http"]),
		auditSink: z.string().min(1),
	})
	.strict();

/** The composition root's adapter selections, as `adaptersSchema` reads them. */
export type Adapters = z.output<typeof adaptersSchema>;

/** A section of keys: an object whose prototype is `Object.prototype` or none. */
export function isPlainSection(value: unknown): value is Readonly<Record<string, unknown>> {
	if (typeof value !== "object" || value === null) return false;
	const prototype: unknown = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

/**
 * `mfaMode`: whether the composition root installs MFA, its own choice — the
 * MFA package's mode, read with that package's schema for `mfa.mode`. `off`
 * installs nothing of MFA; `optional` and `required` install it and are
 * written to `mfa.mode`.
 */
export const mfaSwitchSchema = mfaConfigSchema.shape.mode;

/** The composition root's MFA switch, as `mfaSwitchSchema` reads it. */
export type MfaSwitch = z.output<typeof mfaSwitchSchema>;

/** A YAML file's path: a repository reads its entries from it when it is built. */
const yamlSchema = z.object({ path: z.string() }).strict();

/**
 * `repositories`: the YAML client registry, and the user repository's
 * settings for each adapter it may be — the YAML file, or the Store's HTTP
 * endpoints. `static`, core's alias of `yaml`, reads the same shape from a
 * block of its own, which has no default. The HTTP settings are shape only: the repository holds each
 * value to its rules (https or loopback, a credential's strength, positive
 * whole numbers) when it is built, and names what it refuses.
 */
export const repositoriesSectionSchema = z
	.object({
		client: z.object({ yaml: yamlSchema, static: yamlSchema.optional() }).strict(),
		user: z
			.object({
				yaml: yamlSchema,
				static: yamlSchema.optional(),
				http: z
					.object({
						authenticateUrl: z.unknown().optional(),
						authenticateByTokenUrl: z.unknown().optional(),
						linkFederatedIdentityUrl: z.unknown().optional(),
						findSubjectByFederatedIdentityUrl: z.unknown().optional(),
						markMfaEnrolledUrl: z.unknown().optional(),
						federatedIdentityLookupCoverage: z.unknown().optional(),
						bearerToken: z.unknown().optional(),
						timeout: z.unknown().optional(),
						maxResponseBytes: z.unknown().optional(),
					})
					.strict(),
			})
			.strict(),
	})
	.strict();

/**
 * `repositories` for the adapters `selection` names: `repositoriesSectionSchema`,
 * and the `static` block's path required for a repository that selects
 * `static`, since the block has no default. Refused at the section's parse,
 * naming the path, before any repository is built.
 */
export function repositoriesSectionSchemaFor(selection: {
	readonly client: Adapters["clientRepository"];
	readonly user: Adapters["userRepository"];
}) {
	return repositoriesSectionSchema.superRefine((section, ctx) => {
		for (const repository of ["client", "user"] as const) {
			if (selection[repository] === "static" && section[repository].static === undefined) {
				ctx.addIssue({
					code: "custom",
					path: [repository, "static", "path"],
					message: `required when adapters.${repository}Repository is "static": the static block has no default`,
				});
			}
		}
	});
}

/** The in-process code repository's section: the default lifetime, in positive whole seconds. */
export const inMemoryCodeRepositorySectionSchema = z
	.object({ defaultExpiresIn: wholeNumberInRangeFromEnv(1) })
	.strict();

/**
 * `audit-sink`: each sink's options, keyed by the sink's name, for the sink
 * `adapters.auditSink` selects. Open: the sinks are the factory's, and each
 * builder holds its own options to its rules.
 */
export const auditSinkSectionSchema = z
	.record(z.string(), z.record(z.string(), z.unknown()))
	.optional();
