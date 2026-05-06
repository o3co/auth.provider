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

const signingKeyLocalSchema = z
	.object({
		algorithm: z.enum(["HS256", "RS256", "ES256", "EdDSA"]),
		kid: z.string(),
		secret: z.string().optional(),
		privateKey: z.string().optional(),
		privateKeyPath: z.string().optional(),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		previousKeys: z.array(
			z.object({
				kid: z.string(),
				publicKey: z.string().optional(),
				publicKeyPath: z.string().optional(),
				expiresAt: z.string(),
			}),
		),
	})
	.passthrough();

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
] as const;

const jwtSchemaBase = z.object({
	issuer: z.string().optional(),
	signingKey: signingKeySchema,
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
		refreshToken: z.object({
			expiresIn: z.coerce.number(),
		}),
		grants: z.object({}).passthrough(),
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
			defaultExpiresIn: z.coerce.number().optional(),
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
