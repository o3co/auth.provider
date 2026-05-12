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
 * Schema design principle: pure type contract.
 *
 * Schemas in this file describe the SHAPE that is required to be present at
 * the boundary, not the value that is "reasonable to default to." Defaults
 * live in a single place — `packages/core/config/application.conf` — and
 * `${?ENV_VAR}` substitutions in that file are the only override surface.
 *
 * Consequence: schema parse rejects bare `{}` inputs. Tests that need a
 * valid config must either (a) load it through `parseFile` against the
 * built-in hocon, or (b) supply a minimal schema-valid baseline (e.g.
 * the `makeValidCoreConfig` factory exposed via the
 * `@o3co/auth-provider-core/testing` subpath, which intentionally
 * diverges from `application.conf` for test ergonomics). See
 * ADR 2026-04-30.
 */
import { z } from "zod";

const rateLimitSchema = z.object({
	windowMs: z.coerce.number(),
	limit: z.coerce.number(),
});

const rateLimitSpecSchema = z.object({
	limit: z.coerce.number().int().positive(),
	windowSeconds: z.coerce.number().int().positive(),
});

// IH-9: HS256 key rotation is symmetric — `previousSecrets` carries
// shared secrets keyed by `kid`, distinct from the asymmetric
// `previousKeys` shape (publicKey / publicKeyPath). The schema is split
// via discriminated union so an operator who wires `previousKeys`
// (asymmetric-shaped) under HS256 gets a clear validation error at
// boot rather than silent rotation breakage at the first refresh —
// Codex calibration m1 requires strict() rejection rather than relying
// on field omission, since `.passthrough()` would otherwise let
// `previousKeys` survive into the parsed config.
const hs256PreviousSecretSchema = z.object({
	kid: z.string(),
	secret: z.string(),
	expiresAt: z.string(),
});

const signingKeyLocalHs256Schema = z
	.object({
		algorithm: z.literal("HS256"),
		kid: z.string(),
		secret: z.string().optional(),
		previousSecrets: z.array(hs256PreviousSecretSchema).optional(),
	})
	.strict();

const signingKeyLocalAsymmetricSchema = z
	.object({
		algorithm: z.enum(["RS256", "ES256", "EdDSA"]),
		kid: z.string(),
		privateKey: z.string().optional(),
		privateKeyPath: z.string().optional(),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		// IH-9: optional so the shared HOCON default file can omit
		// `previousKeys = []` without forcing all asymmetric operators
		// to add boilerplate. The factory's `narrowPreviousKeysArray`
		// treats absent/null/[] equivalently.
		previousKeys: z
			.array(
				z.object({
					kid: z.string(),
					publicKey: z.string().optional(),
					publicKeyPath: z.string().optional(),
					expiresAt: z.string(),
				}),
			)
			.optional(),
	})
	.passthrough();

const signingKeyLocalSchema = z.discriminatedUnion("algorithm", [
	signingKeyLocalHs256Schema,
	signingKeyLocalAsymmetricSchema,
]);

const signingKeySchema = z
	.object({
		provider: z.string(),
		local: signingKeyLocalSchema.optional(),
	})
	.passthrough();

const LEGACY_JWT_FIELDS = [
	"algorithm",
	"kid",
	"secret",
	"privateKey",
	"privateKeyPath",
	"publicKey",
	"publicKeyPath",
	"previousKeys",
	"previousSecrets",
] as const;

/**
 * Fields removed from `oauth.refreshToken` at v0.6.0. Detected on the raw
 * input by the preprocess wrapper below so that operators upgrading from
 * v0.5.x get a targeted error instead of having their flag silently
 * stripped by Zod's default `unknown-key strip` behavior.
 */
const REMOVED_REFRESH_TOKEN_FIELDS: ReadonlyArray<{
	name: string;
	removedIn: string;
	note: string;
}> = [
	{
		name: "legacyTokenCompat",
		removedIn: "v0.6.0 (Phase G / M4)",
		note:
			"v0.4.x refresh-token shape compat (payload.type, claims.user.id fallback) is no " +
			"longer accepted. Ensure all in-flight refresh tokens were minted by v0.5.x or newer " +
			"(header.typ = 'rt+jwt' and top-level sub) before upgrading.",
	},
];

const jwtSchemaBase = z.object({
	issuer: z.string().optional(),
	signingKey: signingKeySchema,
	// SF-1 (v0.5.1): when true (default in HOCON), the central JWT verifier
	// accepts tokens whose `typ` header is absent and emits a deprecation
	// warning. v0.6+ should set this to false and reject typ-less tokens.
	// Per the v0.5.1 ADR the literal default lives in `application.conf`.
	legacyTypAccept: z.boolean().optional(),
});

/**
 * jwtSchema wraps the base object schema with a preprocess step that detects
 * legacy flat oauth.jwt.* fields before zod strips unknown keys.
 *
 * Zod's default object behavior strips unknown keys before superRefine sees
 * the data, so superRefine on the parsed output cannot detect stripped fields.
 * z.preprocess runs on the raw input and can emit a ZodError early.
 */
const jwtSchema = z.preprocess((raw, ctx) => {
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
		const rawObj = raw as Record<string, unknown>;
		const legacyPresent = LEGACY_JWT_FIELDS.filter((field) => field in rawObj);
		if (legacyPresent.length > 0) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message:
					`oauth.jwt has legacy flat fields (${legacyPresent.join(", ")}). ` +
					`Migrate to nested shape: oauth.jwt.signingKey.local.<field>. ` +
					`See packages/core/README.md for migration guide.`,
				path: [legacyPresent[0]],
			});
		}
	}
	return raw;
}, jwtSchemaBase);

const refreshTokenSchemaBase = z.object({
	expiresIn: z.coerce.number(),
	// CC-2 (v0.5.1): policy for refresh tokens whose `family_id` does not
	// match a known family record. `"reject"` is the safe default; the
	// pre-fix behavior was implicit `"accept"` (silent fall-through to
	// success). `"accept"` is intended only for time-bounded migration
	// windows. Per the v0.5.1 ADR the literal default lives in
	// `application.conf`, not here.
	unknownFamilyPolicy: z.enum(["accept", "reject"]),
	// SF-6 (v0.5.1) / v0.6.0 (Phase G / M6): policy for refresh tokens
	// lacking `jti` or `family_id` claims when family rotation is wired.
	// The `"accept-with-warning"` migration-window value was removed at
	// v0.6.0; only `"reject"` remains. Operators upgrading from v0.5.x
	// who still set `accept-with-warning` get a Zod
	// `invalid_enum_value` error pointing at this field.
	legacyRtPolicy: z.enum(["reject"]),
});

/**
 * Detects fields removed from `oauth.refreshToken` and emits a targeted
 * Zod issue. Zod's default behavior strips unknown keys before
 * superRefine runs, so without this preprocess wrapper an operator's
 * stale config line (e.g. `legacyTokenCompat = true`) would be silently
 * ignored on upgrade.
 */
const refreshTokenSchema = z.preprocess((raw, ctx) => {
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
		const rawObj = raw as Record<string, unknown>;
		for (const removed of REMOVED_REFRESH_TOKEN_FIELDS) {
			if (removed.name in rawObj) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message:
						`oauth.refreshToken.${removed.name} was removed in ${removed.removedIn}. ` +
						`${removed.note} Remove this field from your config.`,
					path: [removed.name],
				});
			}
		}
	}
	return raw;
}, refreshTokenSchemaBase);

/**
 * Minimal always-required config for the auth provider core.
 * Token-only deployments (no session, no federation) only need these sections.
 */
export const CoreConfigSchema = z.object({
	http: z.object({
		port: z.coerce.number(),
		trustProxy: z.boolean(),
	}),
	oauth: z.object({
		jwt: jwtSchema,
		accessToken: z.object({
			expiresIn: z.coerce.number(),
		}),
		refreshToken: refreshTokenSchema,
		grants: z.object({}).passthrough(),
		// IH-6 (v0.5.3): when acting as an OIDC OP, `/authorize` rejects
		// requests that omit `openid` unless operators explicitly choose dual
		// OAuth/OIDC mode. Shape-only; default lives in HOCON.
		oidcMode: z.enum(["oidc-required", "dual"]),
		// OR-9 (Wave 5d): adapter switch for the OAuth authorization-code
		// repository. Multi-replica deployments MUST set this to `"redis"`;
		// the in-memory variant loses codes on restart and across replicas.
		//
		// `adapter` is `.optional()` (not required-when-code-is-present)
		// because the core HOCON binds it to `${?OAUTH_CODE_ADAPTER}` with
		// no literal default — when the env var is unset, HOCON still
		// produces an empty `oauth.code = {}` block. Requiring `adapter`
		// here would reject that valid "no override" state. The
		// `buildModules` legacy `repositories.code.type = "redis"` fallback
		// only fires when `adapter` is undefined, so leaving it optional
		// is what keeps the deprecation window real.
		code: z
			.object({
				adapter: z.enum(["memory", "redis"]).optional(),
			})
			.optional(),
		// IH-16 (v0.5.1): bound the OIDC `nonce` query parameter at /authorize
		// ingress so a malicious RP cannot exhaust per-request memory or amplify
		// the id_token payload by sending a multi-megabyte nonce. Shape-only —
		// per the v0.5.1 ADR (defaults live in HOCON, not in zod).
		nonce: z
			.object({
				maxLength: z.coerce.number().int().positive(),
			})
			.optional(),
		// F10 (v0.5.3): bound RFC 8693 actor delegation chains so repeated
		// token exchanges cannot grow unbounded nested `act` claims. Shape-only —
		// defaults live in HOCON, not zod.
		tokenExchange: z
			.object({
				maxActorChainDepth: z.coerce.number().int().positive(),
			})
			.optional(),
	}),
});

export type CoreConfig = z.infer<typeof CoreConfigSchema>;

/**
 * Composes a config schema by merging module-specific schemas with the CoreConfigSchema.
 * Each module can declare its required config shape; the resulting schema validates
 * the intersection of core + all module schemas.
 */
export function composeConfigSchema(moduleSchemas: z.ZodObject<z.ZodRawShape>[]): z.ZodType {
	let schema: z.ZodType = CoreConfigSchema;
	for (const moduleSchema of moduleSchemas) {
		schema = schema.and(moduleSchema);
	}
	return schema;
}

/**
 * Env-var-safe boolean coercion for federation `enabled` fields.
 *
 * z.coerce.boolean() calls JavaScript's Boolean(value), so any non-empty string
 * (including "false", "no", "0") coerces to true. This is unsafe for env-var
 * overrides where operators set FEDERATIONS_*_ENABLED=false to disable a federation.
 *
 * This preprocess explicitly maps the common string representations:
 *   "true" | "1"        → true
 *   "false" | "0" | ""  → false
 *   boolean             → pass-through unchanged
 *   other values        → forwarded to z.boolean() which rejects with a type error
 */
const coerceBooleanFromEnv = z.preprocess((val) => {
	if (typeof val === "boolean") return val;
	if (typeof val === "string") {
		const normalized = val.trim().toLowerCase();
		if (normalized === "true" || normalized === "1") return true;
		if (normalized === "false" || normalized === "0" || normalized === "") return false;
	}
	return val; // zod rejects with a type error for other values
}, z.boolean());

const federationEntrySchema = z
	.object({
		enabled: coerceBooleanFromEnv,
		type: z.string().optional(),
	})
	.passthrough();

export const fullSectionsSchema = z.object({
	session: z.object({
		secret: z.string(),
		name: z.string(),
		maxAge: z.coerce.number(),
		secure: z.boolean(),
		sameSite: z.enum(["lax", "none", "strict"]),
		domain: z.string().nullable(),
		storage: z
			.object({
				type: z.string(),
				redis: z
					.object({
						url: z.string(),
						password: z.string().optional(),
					})
					.optional(),
			})
			.passthrough(),
	}),
	/**
	 * Rate-limit config for SESSION routes (e.g. `/session/login` bruteforce
	 * protection). Uses `windowMs` (milliseconds) because this section is
	 * consumed by `express-rate-limit` in
	 * `packages/session/src/routes/Session.mts`.
	 *
	 * IH-18 — config split:
	 * This section ONLY governs session-route rate limiting. OAuth endpoint
	 * rate limiting (`/token`, `/authorize`) is provided via the optional
	 * `rateLimiter` component slot; the built-in module config lives under
	 * `memoryRateLimiter.*` / `redisRateLimiter.*` and uses `windowSeconds`
	 * (seconds) per `RateLimitSpec` in `packages/core/src/ratelimit/types.mts`.
	 * Two independent systems, different keys, different units.
	 */
	rateLimit: z.object({
		login: rateLimitSchema,
		// OR-5: fail-mode policy for the OAuth-endpoint rate limiter when
		// the limiter backend itself errors. `"open"` (default in HOCON)
		// preserves existing fail-open behavior + adds `logger.error`
		// emission so operators see the outage even when the audit sink
		// is also down. `"closed"` returns HTTP 503 + logs — recommended
		// for security-sensitive deployments. No `.default()` per ADR.
		failMode: z.enum(["open", "closed"]),
	}),
	federations: z.record(z.string(), federationEntrySchema),
	repositories: z.object({
		client: z
			.object({
				type: z.string(),
			})
			.passthrough(),
		user: z
			.object({
				type: z.string(),
			})
			.passthrough(),
		code: z
			.object({
				type: z.string(),
			})
			.passthrough(),
	}),
	endpoints: z.object({
		// IH-17: tightened from `z.string().optional()` to `z.string()`. The
		// runtime invariant was already enforced by `oauthModule.configSchema`
		// at boot time; the base schema now matches the contract so AppConfig
		// no longer types the field as optional + downstream consumers don't
		// need null guards. Default `/login` lives in HOCON.
		login: z.object({ url: z.string() }),
		// IH-10: `client` / `authCallback` removed — no production consumer
		// reads them. The pre-fix env-var-only HOCON lines silently leaked
		// values into AppConfig that nothing consumed.
	}),
	cors: z.object({
		allowedOrigins: z.array(z.string()),
	}),
	// D-2 v2: connection-config for the standalone refresh-token-family
	// client. Defaults live in HOCON (`application.conf`) per ADR — no
	// `.default()` here. Module-internal config (`keyPrefix`, `casRetryLimit`)
	// is declared on a SEPARATE top-level key below so AppConfigSchema does
	// not strip it before the boot-time module schema sees it.
	refreshTokenFamilyStore: z
		.object({
			redis: z
				.object({
					url: z.string(),
					password: z.string().optional(),
				})
				.optional(),
		})
		.optional(),
	// Wave 5d (IH-14 + OR-M1): adapter switch for the OAuth-endpoint
	// rate limiter. Default `"memory"` lives in HOCON. NOTE: this is a
	// SEPARATE rate-limit system from `rateLimit.login.windowMs` (which
	// governs session-route bruteforce protection via express-rate-limit
	// in `packages/session/src/routes/Session.mts`). See `RateLimitSpec`
	// JSDoc + `application.conf` comments for the IH-18 split rationale.
	rateLimiter: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// SF-10 (v0.5.3): module-internal config for `memoryRateLimiterModule`.
	// Declared here so AppConfigSchema preserves HOCON/env overrides before
	// module schema validation applies its defaults. Defaults live in HOCON.
	memoryRateLimiter: z
		.object({
			limits: z.record(z.string(), rateLimitSpecSchema).optional(),
			defaultLimit: rateLimitSpecSchema.optional(),
			maxBuckets: z.coerce.number().int().positive().optional(),
		})
		.optional(),
	// Wave 5d (OR-4): adapter switch for the four user-session stores
	// (`userSessionStore`, `sessionRPRegistry`, `sessionFamilyIndex`,
	// `sessionFederationIndex`). Multi-replica deployments MUST set this
	// to `"redis"`; the in-memory variant loses session state on restart
	// and across replicas. Top-level key (not `oauth.session.*`) to avoid
	// confusion with the existing `session.*` cookie/express-session
	// configuration tree (different responsibility, different backend).
	userSessionStores: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// MIN-3 (v0.5.3): preserve the bundled Redis user-session namespace
	// override before `redisSessionStoresModule.configSchema` applies its
	// own defaults. Without this top-level passthrough, AppConfigSchema would
	// strip `redisSessionStores.keyPrefix` before the module sees it.
	redisSessionStores: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// D-2 v2: module-internal config for `redisRefreshTokenFamilyStoreModule`.
	// MUST be declared here (in `fullSectionsSchema`) so `AppConfigSchema.parse(...)`
	// in `app.mts` preserves operator overrides
	// (`REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX` / `..._CAS_RETRY_LIMIT`) before
	// the module's `configSchema` runs at boot time. Without this declaration
	// Zod strips the unknown top-level key and the env-var overrides silently
	// no-op. The actual defaults still live in `application.conf`; this entry
	// is presence-only (both fields optional). The duplicate-source-of-truth
	// concern is intentional: the module's `configSchema` enforces shape +
	// defaults, this schema only ensures the keys survive validation.
	redisRefreshTokenFamilyStore: z
		.object({
			keyPrefix: z.string().optional(),
			casRetryLimit: z.coerce.number().optional(),
		})
		.optional(),
	// OR-9 (Wave 5d): module-internal config for `redisCodeRepositoryModule`.
	// MUST be declared here (in `fullSectionsSchema`) so `AppConfigSchema.parse(...)`
	// in `app.mts` preserves operator overrides
	// (`CLIENT_CODE_KEY_PREFIX` / `CLIENT_CODE_DEFAULT_EXPIRES_IN`) before
	// the module's `configSchema` runs at boot time. Same gotcha as D-2 v2's
	// `redisRefreshTokenFamilyStore` block above. Defaults stay in
	// `application.conf`; this entry is presence-only (both fields optional).
	redisCodeRepository: z
		.object({
			keyPrefix: z.string().optional(),
			// `defaultExpiresIn` is the Redis PX TTL (seconds) for OAuth
			// authorization codes. Constrained to a positive integer: a bad
			// env-var override (`CLIENT_CODE_DEFAULT_EXPIRES_IN=0`, `="-1"`,
			// non-numeric) fails AppConfigSchema parse at boot rather than
			// silently propagating to a Redis PX call that errors per
			// request. Mirrored at the module configSchema level + at the
			// `RedisCodeRepository` constructor for defense in depth.
			// Per Copilot review on PR #122.
			defaultExpiresIn: z.coerce.number().int().positive().optional(),
		})
		.optional(),
});

/**
 * Full application config schema including all optional module sections.
 * Kept as a plain ZodObject (via .extend) for backward compatibility:
 * - consumers can access .shape (e.g. AppConfigSchema.shape.oauth.shape.jwt)
 * - ts.hocon/zod coercion traverses ZodObject shape, not ZodIntersection
 */
export const AppConfigSchema = CoreConfigSchema.extend(fullSectionsSchema.shape);

export type AppConfig = z.infer<typeof AppConfigSchema>;
