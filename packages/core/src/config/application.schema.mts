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
 * live in a single place — `packages/core/config/reference.conf` — and
 * `${?ENV_VAR}` substitutions in that file are the only override surface.
 *
 * Consequence: schema parse rejects bare `{}` inputs. Tests that need a
 * valid config must either (a) load it through `parseFile` against the
 * built-in hocon, or (b) supply a minimal schema-valid baseline (e.g.
 * the `makeValidCoreConfig` factory exposed via the
 * `@o3co/auth-provider-core/testing` subpath, which intentionally
 * diverges from `reference.conf` for test ergonomics). See
 * ADR 2026-04-30.
 */
import { z } from "zod";
import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import { isValidJwksPath } from "../jwks/path.mjs";
import {
	describeWeakSecret,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
} from "../keys/secretEntropy.mjs";

/**
 * Sanity ceiling for a duration expressed in whole seconds: one year.
 *
 * Not a policy — a deployment wanting a 400-day refresh token is a different
 * conversation — but a typo guard. The pairing with `.positive()` is what
 * actually matters (see `readinessTimeoutMs` for the same reasoning): HOCON
 * substitutes an exported-but-empty environment variable as `""`, and
 * `z.coerce.number()` turns `""` into `0`. A zero token lifetime mints tokens
 * that are already expired.
 */
const MAX_DURATION_SECONDS = 31_536_000;

/** The same one-year ceiling for the settings expressed in milliseconds. */
const MAX_DURATION_MS = 31_536_000_000;

const rateLimitSchema = z.object({
	// #282: an empty RATE_LIMIT env var coerces to 0, and a zero window (or a
	// zero limit) turns the /session/login brute-force guard into a no-op
	// while still looking configured.
	windowMs: z.coerce.number().int().positive().max(MAX_DURATION_MS),
	limit: z.coerce.number().int().positive(),
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
 * Fields removed from `oauth.refreshToken`. Detected on the raw input by the
 * preprocess wrapper below so that operators upgrading from v0.5.x get a
 * targeted error instead of having their flag silently stripped by Zod's
 * default `unknown-key strip` behavior.
 *
 * The `removedIn` field carries the released tag plus internal phase marker
 * (e.g., `v0.6.0 (Phase G / M4)`) so the operator-facing error message names
 * the release that performed the removal and the CHANGELOG entry that
 * documents it. Per docs/release-policy.md R5, the released-tag portion is
 * filled in at release-cut time (R6 step 5) — entries added on HEAD between
 * cuts use a neutral value like `"Phase G / M4"` until the next cut.
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

/**
 * Fields removed from `oauth.authorize`. Same mechanism and rationale as
 * `REMOVED_REFRESH_TOKEN_FIELDS` above — detected on the raw input so the
 * operator gets a targeted boot error instead of Zod silently stripping a
 * config line they believe is load-bearing. `reference.conf` deliberately
 * keeps the `${?OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS}` substitution as a
 * tombstone, so a still-exported env var reaches this check too.
 */
const REMOVED_AUTHORIZE_FIELDS: ReadonlyArray<{
	name: string;
	removedIn: string;
	note: string;
}> = [
	{
		name: "allowUnmarkedClients",
		removedIn: "this release (#330)",
		note:
			"The one-time migration flag for the /authorize first-party invariant (#316/#317) is " +
			"gone: a client whose registration does not carry `firstParty: true` is now always " +
			"refused, whatever this key is set to. Mark every client you operate with " +
			"`firstParty: true` (only ones you would trust to receive a user's identity without " +
			"the user being asked), then delete this key and the " +
			"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS environment variable.",
	},
];

const jwtSchemaBase = z.object({
	// The issuer is a property of the deployment, not of a request. It is
	// REQUIRED: `/oauth/token` used to fall back to `req.get("host")` when this
	// was unset, which made `iss` caller-controlled behind a trusted proxy and
	// the resulting tokens non-portable. See `core/src/issuer/canonical.mts`.
	issuer: z.string().superRefine((value, ctx) => {
		const rejection = checkCanonicalIssuer(value);
		if (rejection) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `oauth.jwt.issuer ${describeIssuerRejection(rejection)}`,
			});
		}
	}),
	signingKey: signingKeySchema,
	// JWKS publishing path (OIDC `jwks_uri`). Operator-choosable per OIDC
	// Discovery; defaults to `/.well-known/jwks.json` when unset (applied by
	// `resolveJwksPath`). Must be an absolute path so the JWKS route and the
	// advertised `jwks_uri` agree. See `core/src/jwks/path.mts`.
	jwksPath: z
		.string()
		.refine(isValidJwksPath, {
			message:
				"oauth.jwt.jwksPath must be an absolute path beginning with '/' with no '//', " +
				"dot-segments, query/fragment, backslash, percent-encoding, or control characters",
		})
		.optional(),
	// JWKS response `Cache-Control: public, max-age=<N>` lifetime (seconds).
	// Operator-tunable; defaults to 300 (applied by `resolveJwksCacheMaxAge`).
	// Keep well below the key-overlap window so a rotated kid propagates to
	// caching verifiers in time. See `core/src/jwks/cache.mts`.
	jwksCacheMaxAge: z.number().int().nonnegative().optional(),
	// SF-1 (v0.5.1): when true (default in HOCON), the central JWT verifier
	// accepts tokens whose `typ` header is absent and emits a deprecation
	// warning. v0.6+ should set this to false and reject typ-less tokens.
	// Per the v0.5.1 ADR the literal default lives in `reference.conf`.
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
	// #282: positive and bounded. See MAX_DURATION_SECONDS.
	expiresIn: z.coerce.number().int().positive().max(MAX_DURATION_SECONDS),
	// CC-2 (v0.5.1): policy for refresh tokens whose `family_id` does not
	// match a known family record. `"reject"` is the safe default; the
	// pre-fix behavior was implicit `"accept"` (silent fall-through to
	// success). `"accept"` is intended only for time-bounded migration
	// windows. Per the v0.5.1 ADR the literal default lives in
	// `reference.conf`, not here.
	unknownFamilyPolicy: z.enum(["accept", "reject"]),
	// SF-6 (v0.5.1) / Phase G / M6: policy for refresh tokens lacking
	// `jti` or `family_id` claims when family rotation is wired. The
	// `"accept-with-warning"` migration-window value was removed in this
	// release; only `"reject"` remains. Operators upgrading from v0.5.x
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
						`oauth.refreshToken.${removed.name} was removed in ${removed.removedIn}; see CHANGELOG. ` +
						`${removed.note} Remove this field from your config.`,
					path: [removed.name],
				});
			}
		}
	}
	return raw;
}, refreshTokenSchemaBase);

/**
 * `oauth.authorize` holds no live keys anymore — it exists only to retire
 * `allowUnmarkedClients` loudly (#330). Optional because nothing requires the
 * section; the empty-object case is what `reference.conf` yields when the
 * tombstone env substitution resolves to nothing.
 */
const authorizeSchema = z.preprocess((raw, ctx) => {
	if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
		const rawObj = raw as Record<string, unknown>;
		for (const removed of REMOVED_AUTHORIZE_FIELDS) {
			if (removed.name in rawObj) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					message:
						`oauth.authorize.${removed.name} was removed in ${removed.removedIn}; see CHANGELOG. ` +
						`${removed.note} Remove this field from your config.`,
					path: [removed.name],
				});
			}
		}
	}
	return raw;
}, z.object({}).optional());

/**
 * Env-var-safe boolean coercion for `enabled` fields.
 *
 * z.coerce.boolean() calls JavaScript's Boolean(value), so any non-empty string
 * (including "false", "no", "0") coerces to true. This is unsafe for env-var
 * overrides where operators set e.g. OAUTH_RESOURCE_INDICATOR_ENABLED=false.
 *
 * This preprocess explicitly maps the common string representations:
 *   "true" | "1"        → true
 *   "false" | "0" | ""  → false
 *   boolean             → pass-through unchanged
 *   other values        → forwarded to z.boolean() which rejects with a type error
 *
 * Used by:
 *  - federation `enabled` fields (fullSectionsSchema)
 *  - oauth.resourceIndicator.enabled (Wave 1 §5.3 / RFC 8707)
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

/**
 * Minimal always-required config for the auth provider core.
 * Token-only deployments (no session, no federation) only need these sections.
 */
export const CoreConfigSchema = z.object({
	http: z.object({
		port: z.coerce.number(),
		trustProxy: z.boolean(),
		// Per-probe deadline for the readiness endpoint. Must stay well under
		// the orchestrator's probe timeout, or a partitioned dependency reads
		// as a slow replica rather than an unready one. Shape-only; default
		// lives in HOCON.
		//
		// `.positive()` is load-bearing, not decoration. HOCON substitutes an
		// empty environment variable as `""` — a very common shape in a .env
		// file, a compose `environment:` entry, or a ConfigMap key left blank —
		// and `z.coerce.number()` turns `""` into `0`. `setTimeout` clamps 0 to
		// 1ms, so every probe against a perfectly healthy Redis would time out
		// and the replica would answer 503 forever, draining all traffic with
		// nothing actually wrong. Failing boot loudly is the right outcome.
		// The upper bound is Node's timer range. `setTimeout` silently clamps a
		// delay above 2^31-1 to 1ms, so an operator who wrote a large number
		// meaning "be patient" would get the most impatient possible deadline
		// and a replica that is unready forever — the same failure as the empty
		// string, reached from the opposite direction.
		readinessTimeoutMs: z.coerce.number().int().positive().max(2_147_483_647),
	}),
	// Shape-only; the default lives in HOCON. `silent` is a threshold, not a
	// level anything emits at.
	logging: z.object({
		level: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]),
	}),
	oauth: z.object({
		jwt: jwtSchema,
		accessToken: z.object({
			// #282: positive and bounded. See MAX_DURATION_SECONDS.
			expiresIn: z.coerce.number().int().positive().max(MAX_DURATION_SECONDS),
		}),
		refreshToken: refreshTokenSchema,
		grants: z.object({}).passthrough(),
		// IH-6 (v0.5.3): when acting as an OIDC OP, `/authorize` rejects
		// requests that omit `openid` unless operators explicitly choose dual
		// OAuth/OIDC mode. Shape-only; default lives in HOCON.
		oidcMode: z.enum(["oidc-required", "dual"]),
		// #297: require a Store-published verified email before issuing tokens
		// for an end-user subject. Optional and off by default — `emailVerified`
		// is Store data that many Stores simply do not model, so defaulting this
		// on would refuse every user of every deployment that has not adopted
		// the field. The verification *flow* stays with the Store; this is only
		// a gate on what this library issues.
		requireEmailVerified: z.boolean().optional(),
		// #267: `/authorize` refuses a client not marked `firstParty: true` —
		// one with no `firstParty` field and one carrying an explicit `false`
		// alike. The `allowUnmarkedClients` migration escape hatch that
		// admitted unmarked registrations (#317) was removed in #330; the
		// section survives only as the tombstone that rejects a config still
		// setting the key (see `REMOVED_AUTHORIZE_FIELDS`).
		authorize: authorizeSchema,
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
		// Wave 1 §5.3 (v0.6.x): opt-in gate for RFC 8707 Resource Indicator
		// enforcement. `enabled = false` in reference.conf ensures the feature
		// is off by default; operators set `enabled = true` (or
		// `OAUTH_RESOURCE_INDICATOR_ENABLED=true`) to activate. Shape-only per
		// ADR 2026-04-30 — no `.default()` here; default lives in reference.conf
		// (added in Task 18). `coerceBooleanFromEnv` handles the HOCON
		// env-substitution string → boolean coercion established by PR #171.
		resourceIndicator: z
			.object({
				enabled: coerceBooleanFromEnv,
			})
			.optional(),
		// #277: what `POST /oauth/revoke` promises for ACCESS tokens.
		//
		//   "denylist"    — revoking an access token adds its `jti` to the
		//                   `accessTokenDenylist` component, which token
		//                   verification consults. Boot refuses when the slot is
		//                   unwired: the endpoint would answer RFC 7009's
		//                   mandatory 200 while the JWT stayed valid until expiry.
		//   "unsupported" — this deployment does not revoke access tokens.
		//                   `token_type_hint = access_token` gets RFC 7009 §2.2.1
		//                   `unsupported_token_type`, and no denylist is needed.
		//
		// REFRESH-token revocation is unaffected by this key in either mode — it
		// runs off `refreshTokenFamilyRevocation` and never needed a denylist.
		//
		// `.optional()` with a code-side default of `"denylist"` (see
		// `resolveAccessTokenRevocationMode`), not a HOCON-only default: an
		// embedder hand-building a config object must not fall into the silent
		// no-op by omission. The HOCON layer carries the same literal so the key
		// is discoverable in `reference.conf`.
		revocation: z
			.object({
				accessToken: z.enum(["denylist", "unsupported"]),
			})
			.optional(),
		// Wave 2 cross-mechanism dispatch refactor: declared in core (single
		// source of truth) because the dispatch-policy applies across ALL
		// installed binding-mechanism modules (DPoP, mTLS, ...). Each module
		// no longer redeclares this key in its own schema. Shape-only — the
		// default lives in HOCON (see core reference.conf). The synthesized
		// `tokenBindingMw` in `assembleApp` reads
		// `config.oauth.tokenBinding["dispatch-policy"]` and falls back to
		// `"intent-explicit"` when absent.
		//
		// See ADR `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`
		// for the cross-mechanism design rationale.
		tokenBinding: z
			.object({
				"dispatch-policy": z.enum(["intent-explicit", "strict-mutual-exclusion"]),
			})
			.optional(),
	}),
});

export type CoreConfig = z.infer<typeof CoreConfigSchema>;

/**
 * What `POST /oauth/revoke` does with an access token (#277).
 *
 * `"denylist"` requires an `accessTokenDenylist`; `"unsupported"` declares the
 * capability absent so the endpoint says so on the wire instead of pretending.
 */
export type AccessTokenRevocationMode = "denylist" | "unsupported";

/**
 * Read `oauth.revocation.accessToken` off any config-shaped value, returning
 * `undefined` when the operator has not declared one.
 *
 * Deliberately undefaulted. The two layers that consume this key resolve
 * omission differently, and both are right:
 *
 * - The **boot validator** decides whether a composition may run at all, so
 *   omission there means `"denylist"`. Every config written before #277 omits
 *   the key, and those are exactly the deployments whose revocation endpoint
 *   was answering 200 with nothing behind it. Defaulting to `"unsupported"`
 *   would keep them booting and keep the promise broken.
 * - The **revocation router** decides what to answer given what it was handed.
 *   Handed no denylist and no declaration, it cannot revoke access tokens, and
 *   `unsupported_token_type` is the honest answer. It never returns to a 200
 *   that means nothing.
 *
 * A collapsed default would have to pick one of those and be wrong at the
 * other layer, so the resolution stays at the call sites where the reasoning
 * lives.
 *
 * Accepts `unknown` because both callers hold a config whose static type may
 * predate the key: core's boot validator sees the freshly parsed value as
 * `unknown`, and `packages/oauth` reads through its own options shape.
 */
export function readAccessTokenRevocationMode(
	config: unknown,
): AccessTokenRevocationMode | undefined {
	const mode = (config as { oauth?: { revocation?: { accessToken?: unknown } } } | undefined)?.oauth
		?.revocation?.accessToken;
	if (mode === "unsupported" || mode === "denylist") return mode;
	return undefined;
}

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

const federationEntrySchema = z
	.object({
		enabled: coerceBooleanFromEnv,
		type: z.string().optional(),
	})
	.passthrough();

export const fullSectionsSchema = z.object({
	session: z
		.object({
			// #282: the session secret signs the cookie that IS the
			// authenticated session, so guessing it forges logins. It had no
			// floor at all; it now clears the same 256 bits the JWT signing
			// secret does. Unlike the JWT secret (whose floor lives in the
			// keystore builder because that is the only boundary it crosses),
			// this value goes straight from config into express-session, so
			// the schema is the only place to catch it.
			secret: z.string().superRefine((value, ctx) => {
				const actualBytes = measureSecretEntropyBytes(value);
				if (actualBytes < MIN_SECRET_ENTROPY_BYTES) {
					ctx.addIssue({
						code: z.ZodIssueCode.custom,
						message: describeWeakSecret(actualBytes, {
							configKey: "session.secret",
							envVar: "SESSION_SECRET",
						}),
					});
				}
			}),
			name: z.string(),
			// #282: positive and bounded. A `maxAge` of 0 (what an exported-but-
			// empty SESSION_MAX_AGE coerces to) makes express-session emit a
			// cookie that has already expired, so every request arrives
			// unauthenticated and the deployment looks like a login outage with
			// nothing in the logs.
			maxAge: z.coerce.number().int().positive().max(MAX_DURATION_MS),
			secure: z.boolean(),
			sameSite: z.enum(["lax", "none", "strict"]),
			domain: z.string().nullable(),
			/**
			 * #272 — CSRF policy for the state-changing session routes.
			 *
			 * `.optional()` on purpose: a deployment inheriting `reference.conf`
			 * always has it, and every value has a code-side default, so a
			 * hand-built config (tests, embedders composing their own object) is
			 * not forced to restate a section it has no opinion about.
			 *
			 * `trustedOrigins` is NOT `cors.allowedOrigins`. "May this origin read
			 * my responses" and "may this origin make me change state" are two
			 * questions, and #272 was filed because one list was answering both.
			 * Deployments whose login UI is served from a different origin than
			 * the provider list those origins here — explicitly.
			 */
			csrf: z
				.object({
					trustedOrigins: z.array(z.string()),
					// `.int().positive()` is load-bearing, not decoration — the same
					// trap `http.readinessTimeoutMs` above documents, reached through
					// a different door. The value is used in arithmetic AND
					// stringified into the CSRF token as its expiry field, so every
					// non-conforming value disables the token arm *silently*:
					//
					//   ""   -> HOCON substitutes an empty SESSION_CSRF_TTL_SECONDS as
					//           the empty string and `z.coerce.number()` makes that
					//           `0`, so every minted token is already expired. The
					//           token arm is dead, header-less clients are locked out,
					//           and nothing in the config looks wrong.
					//   0/-n -> the same, stated outright.
					//   7200.5 -> the expiry stringifies as a decimal, which the
					//           token's own shape check rejects. Every token the
					//           provider issues is unverifiable the instant it is
					//           issued, including the one `GET /session/csrf` just
					//           handed the caller.
					//
					// The ceiling is a policy bound, not a mechanical one: a token
					// whose job is to outlive a login form sitting open stops being
					// that and becomes a long-lived bearer value in a JS-readable
					// cookie. It restates `MAX_CSRF_TTL_SECONDS` from
					// `@o3co/auth-provider-session`'s `csrf.mts`, which cannot be
					// imported here (session depends on core, not the reverse); the
					// two are pinned together by a test in that package.
					ttlSeconds: z.coerce.number().int().positive().max(86_400),
				})
				.optional(),
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
		})
		.superRefine((session, ctx) => {
			// #282: every current browser refuses to store a `SameSite=None`
			// cookie that is not also `Secure` (Chrome 80+, Firefox 96+,
			// Safari 13+). The combination is not "less safe" — it is
			// completely non-functional, and it fails on the client with no
			// server-side signal at all, which is why it has to be caught here.
			if (session.sameSite === "none" && session.secure !== true) {
				ctx.addIssue({
					code: z.ZodIssueCode.custom,
					path: ["secure"],
					message:
						'session.sameSite = "none" requires session.secure = true (env ' +
						"SESSION_SECURE=true): browsers drop a SameSite=None cookie that is not " +
						'Secure, so no session would ever be established. Use sameSite = "lax" ' +
						"for local HTTP development.",
				});
			}
		}),
	/**
	 * Rate-limit config for SESSION routes (e.g. `/session/login` bruteforce
	 * protection). Uses `windowMs` (milliseconds) for historical reasons —
	 * the section was shaped by `express-rate-limit`, which
	 * `packages/session/src/routes/Session.mts` consumed until #270.
	 *
	 * Since #270 `/session/login` runs on the shared `rateLimiter` component
	 * instead, keyed `login:ip:<ip>`, so the guard is one bucket set across
	 * replicas rather than one per process. These values stay the single
	 * source of truth: both bundled limiter adapters seed their own
	 * `limits.login` from them (`resolveLoginLimitSpec`), converting to the
	 * whole seconds a `RateLimitSpec` takes.
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
	// client. Defaults live in HOCON (`reference.conf`) per ADR — no
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
	// #271: how many replicas this deployment runs. Read only by the boot
	// replica-safety guard (`checkReplicaSafety`).
	//
	// Deliberately `.optional()` with **no HOCON literal default**, because
	// "unset" is a meaningful third state and a baked-in `"single"` would make
	// it unreachable:
	//   - `"multi"`  → boot fails if any in-memory shared store is wired
	//   - `"single"` → the operator has declared one replica; silent
	//   - unset      → nothing declared; one consolidated warning naming what
	//                  is in memory and what it costs when scaled
	// Same reasoning as `oauth.code.adapter` above, for a different key.
	deployment: z
		.object({
			mode: z.enum(["single", "multi"]).optional(),
		})
		.optional(),
	// Wave 5d (IH-14 + OR-M1): adapter switch for the rate limiter. Default
	// `"memory"` lives in HOCON. Since #270 this one component serves BOTH
	// the OAuth endpoints and `/session/login`, so `"redis"` is what makes
	// either of them safe across replicas. `rateLimit.login.windowMs` remains
	// a separate config *section* — it configures the login window and limit,
	// which the adapters seed into `limits.login` — but no longer a separate
	// rate-limit *system*. See `RateLimitSpec` JSDoc + `reference.conf`
	// comments for the IH-18 split rationale.
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
	// #277: adapter switch for the RFC 7009 access-token denylist. Default
	// `"memory"` lives in HOCON, matching `rateLimiter` / `userSessionStores`.
	//
	// `"memory"` forks per replica — a revocation served by one replica leaves
	// the token working on the others — which is why
	// `core-access-token-denylist-memory` is in the replica-safety guard's
	// refused set. Anything running more than one replica needs `"redis"`, and
	// `deployment.mode = "multi"` enforces that rather than trusting the reading.
	accessTokenDenylist: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// #277: module-internal config for `redisAccessTokenDenylistModule`.
	// Declared here for the same reason as `redisRefreshTokenFamilyStore` below:
	// without a top-level entry, `AppConfigSchema.parse(...)` strips the key
	// before the module's own `configSchema` ever sees the operator's override.
	// Presence-only; the default lives in `reference.conf` and in the module.
	redisAccessTokenDenylist: z
		.object({
			keyPrefix: z.string().optional(),
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
	// no-op. The actual defaults still live in `reference.conf`; this entry
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
	// `reference.conf`; this entry is presence-only (both fields optional).
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
