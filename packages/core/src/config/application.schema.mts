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
 * Zod schemas for the application config. They are a pure type contract: the
 * shape required at the boundary, not defaults. Defaults live only in a
 * `reference.conf` — core's own sections' in `packages/core/config/reference.conf`,
 * a module's in the one its manifest declares — so parsing `{}` fails. Tests load through
 * `parseFile` or start from `makeValidCoreConfig`
 * (`@o3co/auth-provider-core/testing`). See ADR 2026-04-30.
 */
import { z } from "zod";

/**
 * A list an environment variable may carry as one comma-separated string.
 * Entries are trimmed and empties dropped, so `"a, ,b"` is `["a", "b"]` and an
 * exported-but-empty variable is `[]`.
 */
const commaList = z.union([z.array(z.string()), z.string()]).transform((value) =>
	Array.isArray(value)
		? value
		: value
				.split(",")
				.map((entry) => entry.trim())
				.filter((entry) => entry.length > 0),
);

import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import { isWellFormedKid, MAX_KID_LENGTH } from "../keys/kid.mjs";
import {
	describeWeakSecret,
	MIN_SECRET_ENTROPY_BYTES,
	measureSecretEntropyBytes,
} from "../keys/secretEntropy.mjs";
import {
	checkSerializedOrigin,
	describeSerializedOriginRejection,
	normalizeAllowedOrigins,
} from "../net/origin.mjs";
import {
	checkTrustedProxyEntry,
	describeTrustedProxyEntryRejection,
} from "../net/trusted-proxy.mjs";
import { MAX_DURATION_MS, MAX_DURATION_SECONDS } from "./durations.mjs";
import { type RemovedKey, withRemovedKeys } from "./removed-keys.mjs";
import { environmentCoercer } from "./schema-path.mjs";

/**
 * The coercion every env-overridable boolean goes through. HOCON substitutes
 * `${?VAR}` as a string, and the hocon zod bridge coerces only leaves it can
 * reach (object shapes, arrays, optional / default-style wrappers), not ones
 * behind `z.preprocess` or `z.record`. So no env-reachable boolean may be a
 * bare `z.boolean()`.
 *
 * Accepted, trimmed and case-insensitive: `"true"` / `"1"` → true;
 * `"false"` / `"0"` / `""` (an exported-but-empty variable) → false; booleans
 * unchanged. Anything else fails boot, including the bridge's `yes` / `no` /
 * `on` / `off`: `z.coerce.boolean()` would read `"false"` as true, turning a
 * feature on when an operator meant off. Exported so other packages (the
 * federation-grants routes) share this one vocabulary.
 */
export const coerceBooleanFromEnv = environmentCoercer(
	z.preprocess(
		(val) => {
			if (typeof val === "boolean") return val;
			if (typeof val === "string") {
				const normalized = val.trim().toLowerCase();
				if (normalized === "true" || normalized === "1") return true;
				if (normalized === "false" || normalized === "0" || normalized === "") return false;
			}
			return val; // rejected below, with a message naming the accepted spellings
		},
		z.boolean({
			error: 'must be one of "true", "false", "1" or "0" (an empty value reads as false)',
		}),
	),
);

const rateLimitSchema = z.object({
	// An empty env var coerces to 0, and a zero window (or limit) would turn the
	// /session/login brute-force guard into a no-op that still looks configured.
	windowMs: z.coerce.number().int().positive().max(MAX_DURATION_MS),
	limit: z.coerce.number().int().positive(),
});

const rateLimitSpecSchema = z.object({
	limit: z.coerce.number().int().positive(),
	// One year at most, the ceiling of every duration here: a window past the
	// Date range is one the limiter adapters refuse when they are built.
	windowSeconds: z.coerce.number().int().positive().max(MAX_DURATION_SECONDS),
});

// A configured kid is held to the rule `verifyJwt` holds a kid header to
// (`keys/kid.mts`): one it would refuse makes every token signed under it fail
// as the client's fault. The keystores check again when they are built, for a
// composition that builds one without this schema.
const kidSchema = z.string().refine(isWellFormedKid, {
	message: `must be a key id: a string of 1 to ${MAX_KID_LENGTH} characters with no control character`,
});

const hs256PreviousSecretSchema = z.object({
	kid: kidSchema,
	secret: z.string(),
	expiresAt: z.string(),
});

// HS256 rotation keeps shared secrets under `previousSecrets`, not the
// asymmetric `previousKeys`. `.strict()` so `previousKeys` under HS256 fails at
// boot instead of surviving parse and breaking rotation at the first refresh.
const signingKeyLocalHs256Schema = z
	.object({
		algorithm: z.literal("HS256"),
		kid: kidSchema,
		secret: z.string().optional(),
		previousSecrets: z.array(hs256PreviousSecretSchema).optional(),
	})
	.strict();

const signingKeyLocalAsymmetricSchema = z
	.object({
		algorithm: z.enum(["RS256", "ES256", "EdDSA"]),
		kid: kidSchema,
		privateKey: z.string().optional(),
		privateKeyPath: z.string().optional(),
		publicKey: z.string().optional(),
		publicKeyPath: z.string().optional(),
		// Optional so the shared HOCON default can omit `previousKeys = []`; the
		// factory treats absent, null and [] alike.
		previousKeys: z
			.array(
				z.object({
					kid: kidSchema,
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
 * Fields removed from `oauth.refreshToken`, detected on the raw input so an
 * upgrading operator gets a targeted error instead of Zod silently stripping
 * the key. `removedIn` is the release tag plus the phase or PR, so the error
 * names the release and its CHANGELOG entry. An entry added between cuts reads
 * `"this release (#NNN)"` until the cut stamps it (docs/release-policy.md R5,
 * R6), which `removedIn.drift.test.mts` enforces.
 */
const REMOVED_REFRESH_TOKEN_FIELDS: readonly RemovedKey[] = [
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
 * Fields removed from `oauth.authorize`; same mechanism as above.
 * `reference.conf` keeps the `${?OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS}`
 * substitution as a tombstone so a still-exported env var reaches this check.
 */
const REMOVED_AUTHORIZE_FIELDS: readonly RemovedKey[] = [
	{
		name: "allowUnmarkedClients",
		removedIn: "v0.10.0 (#330)",
		note:
			"The one-time migration flag for the /authorize first-party invariant (#316/#317) is " +
			"gone: a client whose registration does not carry `firstParty: true` is now always " +
			"refused, whatever this key is set to. Mark every client you operate with " +
			"`firstParty: true` (only ones you would trust to receive a user's identity without " +
			"the user being asked), then delete this key and the " +
			"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS environment variable.",
	},
];

/**
 * Fields removed from `oauth.dpop`; same mechanism as above. Failed rather than
 * ignored (docs/release-policy.md "Retiring a config key"): a deployment that
 * wired a shared DPoP store beside a memory seen-set would otherwise move its
 * DPoP records into memory silently.
 */
const REMOVED_DPOP_FIELDS: readonly RemovedKey[] = [
	{
		name: "replay-store",
		removedIn: "v0.16.0 (#673)",
		note:
			"Every accepted DPoP proof is now recorded in the replaySeenSet component — the " +
			"seen-set private_key_jwt client authentication and WebAuthn record in — and the " +
			"dpopReplayStore slot is gone. Choose the backend there: redisReplaySeenSetModule " +
			'shares it across replicas (replaySeenSet.adapter = "redis" in the standalone ' +
			'template), and core.deployment.mode = "multi" refuses the memory one.',
	},
];

/**
 * A duration read strictly: a number, or the plain decimal string an
 * environment variable arrives as. Not `z.coerce.number()`, which reads `null`
 * and `[]` as 0, `true` as 1 and `"1e3"` as 1000: a malformed duration would be
 * normalised (`tombstoneRetention: null` disabling tombstones) instead of
 * failing boot naming the key.
 * @internal
 */
export const durationFromEnv = (bounds: z.ZodNumber) =>
	environmentCoercer(
		z.preprocess((value) => {
			if (typeof value === "number") return value;
			if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
			// Handed through unchanged, and refused by `bounds` with a message that
			// names what is acceptable.
			return value;
		}, bounds),
	);

const jwtSchemaBase = z.object({
	// Required: the issuer belongs to the deployment, never to a request. An
	// `iss` derived from the Host header is caller-controlled behind a trusted
	// proxy. See `core/src/issuer/canonical.mts`.
	issuer: z.string().superRefine((value, ctx) => {
		const rejection = checkCanonicalIssuer(value);
		if (rejection) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				message: `oauth.jwt.issuer ${describeIssuerRejection(rejection)}`,
			});
		}
	}),
	// The section of the module that provides `keyStore`; core reads none of it
	// and ships no default.
	signingKey: signingKeySchema.optional(),
	// When true, the JWT verifier accepts tokens with no `typ` header and warns.
	// No schema default: `reference.conf` ships `false` (a typ-less token is a
	// misconfiguration or downgrade signal); `OAUTH_JWT_LEGACY_TYP_ACCEPT=true`
	// is a migration override. `coerceBooleanFromEnv` because this section sits
	// behind `z.preprocess`, which the hocon bridge does not coerce through.
	legacyTypAccept: coerceBooleanFromEnv.optional(),
});

/**
 * Detects legacy flat `oauth.jwt.*` fields on the raw input: Zod strips unknown
 * keys before `superRefine` runs, so only `z.preprocess` can see them. This
 * pipe's `out.shape.signingKey` is read as the signing-key section's schema:
 * keep that path, or change its readers with it.
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
 * `oauth.accessToken` once the schema has parsed it.
 *
 * Read the lifetime through {@link resolveAccessTokenLifetime}, not through
 * these fields: `defaultExpiresIn` and `maxExpiresIn` are present only when
 * configured, and the rules that fill them in live in the resolver.
 */
export interface AccessTokenConfig {
	/**
	 * The lifetime, in seconds, every grant mints when the request does not ask
	 * for one — and every grant but token exchange never lets it ask. Absent
	 * when unset, in which case the deprecated `expiresIn` supplies it.
	 */
	defaultExpiresIn?: number;
	/**
	 * The most a token-exchange request's `expires_in` can obtain; a larger
	 * request is clamped to it. Absent when unset, which means the default: no
	 * request extends past it unless the operator opts in.
	 */
	maxExpiresIn?: number;
	/**
	 * The resolved default lifetime, in seconds, mirrored so readers of this key
	 * mint what every other grant mints.
	 *
	 * @deprecated As a configuration key, an alias of `defaultExpiresIn`; readers
	 * should call `resolveAccessTokenLifetime`. See CHANGELOG.
	 */
	expiresIn: number;
}

/** What {@link resolveAccessTokenLifetime} answers. */
export interface AccessTokenLifetime {
	/** Seconds minted when the request asks for no particular lifetime. */
	readonly defaultExpiresIn: number;
	/** Seconds no request can exceed. Never below `defaultExpiresIn`. */
	readonly maxExpiresIn: number;
}

/**
 * Anything carrying an `oauth.accessToken` section: a loaded `AppConfig`, or
 * a configuration built by hand that never met the schema. Values are
 * `unknown` because the resolver validates them rather than trusting a type.
 */
export interface AccessTokenLifetimeSource {
	readonly oauth: {
		readonly accessToken?: {
			readonly defaultExpiresIn?: unknown;
			readonly maxExpiresIn?: unknown;
			readonly expiresIn?: unknown;
		};
	};
}

const ACCESS_TOKEN_LIFETIME_KEYS = ["defaultExpiresIn", "maxExpiresIn", "expiresIn"] as const;

type AccessTokenLifetimeKey = (typeof ACCESS_TOKEN_LIFETIME_KEYS)[number];

/**
 * Whether a value is a token lifetime this provider accepts: whole seconds from
 * 1 to `MAX_DURATION_SECONDS`. Both lifetime resolvers apply it; hold a lifetime
 * handed over as a number to it too, so a grant built by hand and one built
 * through its module accept the same values.
 */
export const isLifetimeSeconds = (value: unknown): value is number =>
	typeof value === "number" &&
	Number.isInteger(value) &&
	value > 0 &&
	value <= MAX_DURATION_SECONDS;

type AccessTokenLifetimeCheck =
	| { readonly ok: true; readonly lifetime: AccessTokenLifetime }
	| { readonly ok: false; readonly key: AccessTokenLifetimeKey; readonly message: string };

/**
 * The lifetime rules, shared by the schema refinement and the resolver.
 * `defaultExpiresIn` wins over the deprecated `expiresIn` whenever set, and a
 * disagreement cannot fail boot: `reference.conf` keeps the shipped literal on
 * `expiresIn`, so a configuration using the new key always carries both.
 */
function checkAccessTokenLifetime(
	accessToken: AccessTokenLifetimeSource["oauth"]["accessToken"],
): AccessTokenLifetimeCheck {
	for (const key of ACCESS_TOKEN_LIFETIME_KEYS) {
		const value = accessToken?.[key];
		if (value !== undefined && !isLifetimeSeconds(value)) {
			return {
				ok: false,
				key,
				message: `oauth.accessToken.${key} must be a whole number of seconds from 1 to ${MAX_DURATION_SECONDS} (got ${typeof value === "string" ? JSON.stringify(value) : String(value)})`,
			};
		}
	}
	const configuredDefault = accessToken?.defaultExpiresIn as number | undefined;
	const aliasDefault = accessToken?.expiresIn as number | undefined;
	const defaultExpiresIn = configuredDefault ?? aliasDefault;
	if (defaultExpiresIn === undefined) {
		return {
			ok: false,
			key: "defaultExpiresIn",
			message:
				"oauth.accessToken.defaultExpiresIn is required (OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN); the deprecated oauth.accessToken.expiresIn is still read in its place",
		};
	}
	const maxExpiresIn = (accessToken?.maxExpiresIn as number | undefined) ?? defaultExpiresIn;
	if (defaultExpiresIn > maxExpiresIn) {
		const source =
			configuredDefault === undefined
				? ", read from the deprecated oauth.accessToken.expiresIn"
				: "";
		return {
			ok: false,
			key: "maxExpiresIn",
			message: `oauth.accessToken.defaultExpiresIn (${defaultExpiresIn}${source}) must not exceed oauth.accessToken.maxExpiresIn (${maxExpiresIn}): lower the default or raise the max`,
		};
	}
	return { ok: true, lifetime: { defaultExpiresIn, maxExpiresIn } };
}

/**
 * The access-token lifetime a deployment configured: the default minted when a
 * request asks for nothing, and the max no request may exceed. Every grant
 * reads it through this function when it is built.
 *
 * - `defaultExpiresIn` when set, otherwise the deprecated `expiresIn`;
 * - `maxExpiresIn` when set, otherwise the default, so nothing is extended past
 *   the default unless the operator opts in.
 *
 * The schema enforces the same rules at boot; they are repeated for
 * configurations built by hand, so a bad value fails when the grant is built
 * rather than after a request's single-use credential is spent. The alias is
 * resolved here, not in HOCON, because `parseFile` resolves substitutions per
 * file before the layers merge. {@link resolveRefreshTokenLifetime} is the
 * refresh token's counterpart.
 *
 * @throws RangeError naming the key, for a missing default, a default above the
 * max, or a value that is not whole seconds within the one-year ceiling.
 */
export function resolveAccessTokenLifetime(config: AccessTokenLifetimeSource): AccessTokenLifetime {
	const check = checkAccessTokenLifetime(config.oauth?.accessToken);
	if (!check.ok) throw new RangeError(check.message);
	return check.lifetime;
}

/**
 * Anything carrying an `oauth.refreshToken` section: a loaded `AppConfig`, or
 * a configuration built by hand that never met the schema. The value is
 * `unknown` because the resolver validates it rather than trusting a type.
 */
export interface RefreshTokenLifetimeSource {
	readonly oauth?: { readonly refreshToken?: { readonly expiresIn?: unknown } };
}

/**
 * The refresh-token lifetime a deployment configured, in seconds
 * (`oauth.refreshToken.expiresIn`), and the one reader of that key: every grant
 * minting a refresh token reads it when built, as does the subject-revocation
 * horizon. The schema refuses bad values at boot; the check is repeated for
 * hand-built configurations so a grant fails when built, not after spending a
 * code or challenge or signing a refresh token with no `exp`.
 *
 * @throws RangeError naming the key, for anything but whole seconds from 1 to
 * the one-year ceiling (`isLifetimeSeconds`), absence included.
 */
export function resolveRefreshTokenLifetime(config: RefreshTokenLifetimeSource): number {
	const value = config.oauth?.refreshToken?.expiresIn;
	if (!isLifetimeSeconds(value)) {
		throw new RangeError(
			`oauth.refreshToken.expiresIn must be a whole number of seconds from 1 to ${MAX_DURATION_SECONDS} (got ${typeof value === "string" ? JSON.stringify(value) : String(value)})`,
		);
	}
	return value;
}

/**
 * A lifetime in whole seconds, positive and bounded, so the exported-but-empty
 * variable that `z.coerce.number()` reads as `0` fails boot.
 */
const lifetimeSecondsSchema = z.coerce.number().int().positive().max(MAX_DURATION_SECONDS);

/**
 * `oauth.accessToken`. Every key is optional so either spelling of the default
 * can stand alone; the refinement requires one and refuses a default above the
 * max. The output mirrors the resolved default onto `expiresIn` for readers of
 * that key. The mirror must stay idempotent: `createApp` parses the loaded
 * configuration a second time.
 */
const accessTokenSchema = z
	.object({
		defaultExpiresIn: lifetimeSecondsSchema.optional(),
		maxExpiresIn: lifetimeSecondsSchema.optional(),
		/**
		 * @deprecated An alias of `defaultExpiresIn`, still read when that key is
		 * unset. See CHANGELOG.
		 */
		expiresIn: lifetimeSecondsSchema.optional(),
	})
	.superRefine((value, ctx) => {
		// A value that failed its own leaf check is already reported by name;
		// a cross-field complaint built on it would only be noise.
		if (
			ACCESS_TOKEN_LIFETIME_KEYS.some(
				(key) => value[key] !== undefined && !isLifetimeSeconds(value[key]),
			)
		) {
			return;
		}
		const check = checkAccessTokenLifetime(value);
		if (!check.ok) {
			ctx.addIssue({ code: z.ZodIssueCode.custom, message: check.message, path: [check.key] });
		}
	})
	.transform(
		({ defaultExpiresIn, maxExpiresIn, expiresIn }): AccessTokenConfig => ({
			...(defaultExpiresIn !== undefined ? { defaultExpiresIn } : {}),
			...(maxExpiresIn !== undefined ? { maxExpiresIn } : {}),
			// The refinement above guarantees one of the two; the transform does
			// not run on a value that failed it.
			expiresIn: (defaultExpiresIn ?? expiresIn) as number,
		}),
	);

const refreshTokenSchemaBase = z.object({
	// Positive and bounded (`MAX_DURATION_SECONDS`): the rule
	// `resolveRefreshTokenLifetime` holds a hand-built configuration to.
	expiresIn: lifetimeSecondsSchema,
	// Policy for refresh tokens whose `family_id` matches no family record.
	// `"reject"` is the safe choice; `"accept"` is only for time-bounded
	// migration windows. The default lives in `reference.conf`.
	unknownFamilyPolicy: z.enum(["accept", "reject"]),
	// Refresh tokens lacking `jti` or `family_id` while family rotation is wired
	// are rejected. `"reject"` is the only value, so a stale
	// `accept-with-warning` fails boot on this field.
	legacyRtPolicy: z.enum(["reject"]),
});

/**
 * Fields removed from `oauth.refreshToken` fail boot via `withRemovedKeys`; see
 * `./removed-keys.mts` for why detection runs on the raw input.
 */
const refreshTokenSchema = withRemovedKeys(
	"oauth.refreshToken",
	REMOVED_REFRESH_TOKEN_FIELDS,
	refreshTokenSchemaBase,
);

/**
 * One `oauth.authorize.acrValues` entry: `amr` values a session must all carry,
 * or a list of such lists, any one of which suffices —
 * `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]`. An empty list or alternative is
 * refused: every session would satisfy it.
 */
const acrAlternativeSchema = z.array(z.string().min(1)).min(1);
const acrRequirementSchema = z.union([acrAlternativeSchema, z.array(acrAlternativeSchema).min(1)]);

/**
 * `oauth.authorize`: one live key, `acrValues`, plus the retired
 * `allowUnmarkedClients`. Optional: `reference.conf` declares `acrValues {}`,
 * and the tombstone env substitution resolves to nothing unless a stale
 * variable is still exported.
 */
const authorizeSchema = withRemovedKeys(
	"oauth.authorize",
	REMOVED_AUTHORIZE_FIELDS,
	z
		.object({
			// The Authentication Context Class References this deployment can
			// vouch for, each mapped to the RFC 8176 `amr` values that satisfy it.
			// `/authorize` answers `acr_values` from this table alone (an acr not
			// here is refused), and discovery advertises the keys as
			// `acr_values_supported`, less entries nothing installed can satisfy
			// (dropped at boot with a log line).
			acrValues: z.record(z.string().min(1), acrRequirementSchema).optional(),
		})
		.optional(),
);

/**
 * Ceiling for `http.trustProxy` as a hop count: a typo guard, not a policy. A
 * large number meant as "trust everything" would silently grant the blanket
 * trust `true` states openly. Exported so the `httpSettings` contract suite
 * holds the slot to the same ceiling.
 */
export const MAX_TRUST_PROXY_HOPS = 255;

/**
 * A decimal, optionally signed or fractional: the env-var shapes meant as a hop
 * count. `-1` and `1.5` match on purpose, so they fail as bad hop counts rather
 * than read as one-entry address lists; `10.0.0.7` and `loopback` do not match.
 */
const NUMERIC_STRING = /^-?[0-9]+(\.[0-9]+)?$/;

/**
 * Normalises the config source's value into one of Express's `trust proxy`
 * shapes. HOCON substitutes `${?HTTP_TRUST_PROXY}` as a string, and a union
 * gives the hocon bridge nothing to coerce towards, so the mapping lives here.
 * Separate from `coerceBooleanFromEnv` on purpose: `1` and `0` are hop counts
 * here, not booleans; `true` / `false` / `""` agree.
 */
const normalizeTrustProxy = (raw: unknown): unknown => {
	if (Array.isArray(raw)) {
		return raw.map((entry) => (typeof entry === "string" ? entry.trim() : entry));
	}
	if (typeof raw !== "string") return raw;

	const value = raw.trim();
	// An exported-but-empty variable is the .env / compose / ConfigMap shape
	// that arrives as "". Fail closed rather than guessing at a policy.
	if (value === "") return false;

	const lower = value.toLowerCase();
	if (lower === "true") return true;
	if (lower === "false") return false;
	if (NUMERIC_STRING.test(value)) return Number(value);

	// A trailing comma is the ordinary list typo; dropping the empty tail is
	// friendlier than reporting an "empty entry" the operator never wrote.
	return value
		.split(",")
		.map((entry) => entry.trim())
		.filter((entry) => entry !== "");
};

/**
 * `http.trustProxy`, handed straight to Express's `trust proxy`:
 *
 * - `false`: trust nothing; `req.ip` is the socket peer. The default.
 * - `true`: trust every hop. Correct only when nothing but the proxy can reach
 *   this process; otherwise anyone can choose `req.ip` and forge a rate-limit
 *   identity.
 * - a hop count: trust that many hops back from the socket peer.
 * - an address list: IP literals, CIDR ranges or named ranges (`loopback`,
 *   `linklocal`, `uniquelocal`); the only shape that says which hop is trusted.
 *
 * Entries are validated with `../net/trusted-proxy`, the vocabulary
 * `@o3co/auth-provider-mtls` uses, so a typo fails at boot naming its index
 * instead of silently never matching.
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
					code: z.ZodIssueCode.custom,
					message: `http.trustProxy[${index}] ${describeTrustedProxyEntryRejection(rejection)}`,
					path: [index],
				});
			}
		});
	});

/**
 * Minimal always-required config for the auth provider core.
 * Token-only deployments (no session, no federation) only need these sections.
 * The modules owning `logging`, `http` and `oauth.jwt.signingKey` parse their
 * sections with the declarations here until they have schemas of their own.
 */
export const CoreConfigSchema = z.object({
	// The section of the module that provides `httpSettings`; core reads none
	// of it and ships no default.
	http: z
		.object({
			port: z.coerce.number(),
			// Boolean, hop count or address list. See `trustProxySchema`.
			trustProxy: trustProxySchema,
			// Per-probe deadline for the readiness endpoint; keep it well under the
			// orchestrator's probe timeout, or a partitioned dependency reads as a
			// slow replica instead of an unready one. Bounded both ways because
			// `setTimeout` turns 0 (an empty env var through `z.coerce.number()`)
			// and anything above 2^31-1 into 1ms: every probe would time out and
			// the replica would answer 503 with nothing wrong.
			readinessTimeoutMs: z.coerce.number().int().positive().max(2_147_483_647),
		})
		.optional(),
	// The composition root's logging module's section; core reads none of it
	// and ships no default. `silent` is a threshold, not a level.
	logging: z
		.object({
			level: z.enum(["trace", "debug", "info", "warn", "error", "fatal", "silent"]),
		})
		.optional(),
	oauth: z.object({
		jwt: jwtSchema,
		// The access-token lifetime: `defaultExpiresIn`, `maxExpiresIn`, and the
		// deprecated `expiresIn` alias. See `accessTokenSchema` and
		// `resolveAccessTokenLifetime`.
		accessToken: accessTokenSchema,
		refreshToken: refreshTokenSchema,
		grants: z.object({}).passthrough(),
		// As an OIDC OP, `/authorize` rejects requests without `openid` unless the
		// operator chooses dual OAuth/OIDC mode. Default in HOCON.
		oidcMode: z.enum(["oidc-required", "dual"]),
		// Require a Store-published verified email before issuing tokens for an
		// end-user subject. Off by default: many Stores do not model
		// `emailVerified`, and turning it on would refuse all their users. The
		// verification flow stays with the Store; this only gates issuance.
		requireEmailVerified: coerceBooleanFromEnv.optional(),
		// Deployment-wide deny-by-absence for `allowedGrantTypes`. Per client, an
		// absent allowlist means every grant, so registrations without the field
		// keep working; the secure posture is otherwise opt-in per registration.
		// Off by default: turning it on says the operator audited their
		// registrations. Composes with the per-grant
		// `requiresExplicitGrantAllowlist` to the stricter of the two.
		requireGrantTypeAllowlist: coerceBooleanFromEnv.optional(),
		// `/authorize` refuses a client not marked `firstParty: true` (a missing
		// field and an explicit `false` alike). The section carries `acrValues`
		// and the tombstone for the removed `allowUnmarkedClients` (see
		// `REMOVED_AUTHORIZE_FIELDS`).
		authorize: authorizeSchema,
		// Adapter for the OAuth authorization-code repository. Multi-replica
		// deployments MUST use `"redis"`: memory loses codes on restart and across
		// replicas. Optional because HOCON binds it to `${?OAUTH_CODE_ADAPTER}`
		// with no literal, leaving `oauth.code = {}` when unset, and
		// `buildModules` falls back to the deprecated `repositories.code.type`
		// only when `adapter` is undefined.
		code: z
			.object({
				adapter: z.enum(["memory", "redis"]).optional(),
			})
			.optional(),
		// The RFC 8628 device-grant section `deviceGrantModule` reads, mirrored so
		// a parse through this strip-mode object keeps it. Presence-only: defaults
		// and real bounds live in the device-grant package's `reference.conf` and
		// `deviceGrantConfigSchema`; enum-shaped keys keep their vocabulary so a
		// typo fails here by name.
		deviceAuthorization: z
			.object({
				enabled: coerceBooleanFromEnv.optional(),
				"verification-uri": z.string().optional(),
				"verification-uri-complete": coerceBooleanFromEnv.optional(),
				"code-lifetime-seconds": z.coerce.number().int().positive().optional(),
				"polling-interval-seconds": z.coerce.number().int().positive().optional(),
				rateLimit: z
					.object({
						limit: z.coerce.number().int().positive(),
						windowSeconds: z.coerce.number().int().positive().max(MAX_DURATION_SECONDS),
					})
					.optional(),
				// The declared-absence spelling for the `deviceCodeStore` slot;
				// `"unsupported"` is the only value the module accepts.
				store: z.literal("unsupported").optional(),
			})
			.optional(),
		// Bounds the OIDC `nonce` at /authorize so a malicious RP cannot exhaust
		// per-request memory or bloat the id_token. Default in HOCON.
		nonce: z
			.object({
				maxLength: z.coerce.number().int().positive(),
			})
			.optional(),
		// Bounds RFC 8693 actor delegation chains so repeated token exchanges
		// cannot nest `act` claims without limit. Default in HOCON.
		tokenExchange: z
			.object({
				maxActorChainDepth: z.coerce.number().int().positive(),
			})
			.optional(),
		// Opt-in RFC 8707 Resource Indicator enforcement; off in reference.conf
		// (`OAUTH_RESOURCE_INDICATOR_ENABLED=true` turns it on).
		resourceIndicator: z
			.object({
				enabled: coerceBooleanFromEnv,
			})
			.optional(),
		// Client ID Metadata Documents: a `client_id` that is the https URL of the
		// client's own registration (draft-ietf-oauth-client-id-metadata-document;
		// the MCP 2026-07-28 registration model). Off by default. List keys also
		// take a comma-separated string, for environment variables. Every ceiling
		// here is the operator's: a document says who a client is, never what it
		// may reach.
		clientIdMetadataDocuments: z
			.object({
				enabled: coerceBooleanFromEnv,
				allowedScopes: commaList.optional(),
				allowedAudiences: commaList.optional(),
				allowedHosts: commaList.optional(),
				deniedHosts: commaList.optional(),
				maxBytes: z.coerce.number().int().positive().optional(),
				timeoutMs: z.coerce.number().int().positive().optional(),
				cacheMaxAgeMs: z.coerce.number().int().nonnegative().optional(),
				maxCacheEntries: z.coerce.number().int().positive().optional(),
				staleIfErrorMs: z.coerce.number().int().nonnegative().optional(),
				negativeCacheMs: z.coerce.number().int().nonnegative().optional(),
				maxConcurrentFetches: z.coerce.number().int().positive().optional(),
			})
			.optional(),
		// What `POST /oauth/revoke` promises for access tokens:
		//   "denylist"    — the `jti` goes into the `accessTokenDenylist`
		//                   component that verification consults. Boot refuses an
		//                   unwired slot: RFC 7009's mandatory 200 would otherwise
		//                   leave the JWT valid until expiry.
		//   "unsupported" — `token_type_hint = access_token` gets RFC 7009
		//                   §2.2.1 `unsupported_token_type`; no denylist needed.
		// Refresh-token revocation is unaffected (`refreshTokenFamilyRevocation`).
		// Optional with no default in schema or code (see
		// `readAccessTokenRevocationMode`); `reference.conf` carries `"denylist"`
		// so the key is discoverable.
		revocation: z
			.object({
				accessToken: z.enum(["denylist", "unsupported"]),
				// The declared-absence spelling for both subject-level revocation
				// slots (`subjectRevocation`, `subjectSessionIndex`). One key because
				// they are one capability: the index enumerates what a credential
				// change cascades over, the watermark refuses what it missed. Read
				// only when a slot is unfilled.
				subject: z.enum(["watermark", "unsupported"]).optional(),
			})
			.optional(),
		// Declared in core because the dispatch policy spans every installed
		// binding mechanism (DPoP, mTLS, ...). Default in HOCON; `assembleApp`'s
		// `tokenBindingMw` reads it through `resolveTokenBindingSettings`
		// (`"intent-explicit"` when absent), and no slot carries it. See
		// `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`.
		tokenBinding: z
			.object({
				"dispatch-policy": z.enum(["intent-explicit", "strict-mutual-exclusion"]),
				// Bind a confidential client's refresh token to the presented DPoP
				// key or client certificate, as is always done for public clients.
				// RFC 9449 §5 and RFC 8705 §7.1 neither require nor forbid it: a
				// confidential client authenticates on refresh, and this
				// implementation refuses an unauthenticated caller and an RT whose
				// `azp` is not that client. Hardening for deployments whose key is
				// better protected than the client secret (HSM or TPM vs an env var).
				// Off by default: a bound RT pins the client to one key for its whole
				// lifetime, so rotating mid-lifetime breaks refresh. Core's, like
				// `dispatch-policy`, read through `resolveTokenBindingSettings`.
				bindConfidentialClientRefreshTokens: coerceBooleanFromEnv.optional(),
			})
			.optional(),
		// The two binding-mechanism sections `tokenBinding` dispatches over,
		// mirrored so a parse through this strip-mode object keeps them. A lost
		// section is the quietest failure: `enabled` falls to the module's
		// `false` and the mechanism reads as switched off, not misconfigured, with
		// its boot refusals never seeing the config. Presence-only: bounds and
		// defaults stay in `mtlsConfigSchema` / `dpopConfigSchema` and each
		// package's `reference.conf`; enum-shaped keys keep their vocabulary so a
		// typo fails here by name.
		mtls: z
			.object({
				enabled: coerceBooleanFromEnv.optional(),
				source: z.enum(["header", "tls-layer"]).optional(),
				"cert-header": z.string().optional(),
				"cert-header-dialect": z.enum(["envoy", "plain-pem"]).optional(),
				"trusted-proxies": z.array(z.string()).optional(),
				mode: z.enum(["self-signed", "pki", "full-pki"]).optional(),
				"trusted-cas": z.array(z.string()).optional(),
				"full-pki": z
					.object({
						"max-chain-depth": z.coerce.number().int().positive().optional(),
						// Strings, not an enum: the mtls package owns and checks this
						// vocabulary, and a copy here would drift.
						"signature-algorithms": z.array(z.string()).optional(),
						"min-rsa-key-bits": z.coerce.number().int().positive().optional(),
						// No defaults anywhere: the module refuses boot unless the
						// operator writes `mode` and `on-unavailable`, and it can only
						// see what survives this parse.
						revocation: z
							.object({
								mode: z.enum(["crl", "ocsp", "both", "disabled"]).optional(),
								"on-unavailable": z.enum(["reject", "allow"]).optional(),
								"allowed-hosts": z.array(z.string()).optional(),
								"fetch-timeout-ms": z.coerce.number().int().positive().optional(),
								"cache-ttl-seconds": z.coerce.number().int().nonnegative().optional(),
								"max-response-bytes": z.coerce.number().int().positive().optional(),
								"ocsp-require-nonce": coerceBooleanFromEnv.optional(),
							})
							.optional(),
					})
					.optional(),
			})
			.optional(),
		// `replay-store` is retired loudly (REMOVED_DPOP_FIELDS). Every field
		// below owns its coercion, which the preprocess wrapper requires.
		dpop: withRemovedKeys(
			"oauth.dpop",
			REMOVED_DPOP_FIELDS,
			z
				.object({
					enabled: coerceBooleanFromEnv.optional(),
					"iat-window-seconds": z.coerce.number().int().positive().optional(),
					"alg-whitelist": z.array(z.string()).optional(),
					"replay-store-ttl-seconds": z.coerce.number().int().positive().optional(),
					// Server-provided nonce; the module's own schema defaults it.
					nonce: z
						.object({
							required: z.enum(["never", "as", "as+rs"]).optional(),
							"ttl-seconds": z.coerce.number().int().positive().optional(),
							secret: z.string().optional(),
						})
						.optional(),
				})
				.optional(),
		),
	}),
	// Core's own section.
	core: z
		.object({
			// How many replicas this deployment runs, read by core alone
			// (`deployment/mode.mts`): the boot replica-safety guard
			// (`checkReplicaSafety`) decides by it, and boot fills the
			// `deploymentMode` slot with it for every module that refuses or warns
			// by it. Optional with no HOCON literal, because unset is a meaningful
			// third state:
			//   - `"multi"`  → boot fails if any in-memory shared store is wired
			//   - `"single"` → the operator has declared one replica; silent
			//   - unset      → one consolidated warning naming what is in memory
			//                  and what it costs when scaled
			deployment: z
				.object({
					mode: z.enum(["single", "multi"]).optional(),
				})
				.optional(),
			// The requirement names a composition expects (session-admission ADR),
			// compared at the end of boot's stage 4 with what registered, both ways
			// once written. Required whenever a consumer of admission is installed,
			// `[]` allowed, and no default anywhere: every composition states its
			// posture.
			sessionRequirements: z
				.object({
					expected: z.array(
						z.string().min(1, {
							error: "core.sessionRequirements.expected names each requirement",
						}),
					),
				})
				.optional(),
		})
		.optional(),
});

export type CoreConfig = z.infer<typeof CoreConfigSchema>;

/**
 * What `POST /oauth/revoke` does with an access token. `"denylist"` requires an
 * `accessTokenDenylist`; `"unsupported"` declares the capability absent, so the
 * endpoint says so on the wire instead of pretending.
 */
export type AccessTokenRevocationMode = "denylist" | "unsupported";

/**
 * Reads `oauth.revocation.accessToken` off any config-shaped value; `undefined`
 * when undeclared. Deliberately undefaulted, because its two consumers resolve
 * omission differently and both are right:
 *
 * - boot reads omission as `"denylist"` (`ACCESS_TOKEN_DENYLIST_ABSENCE_POLICY`:
 *   only an explicit `"unsupported"` excuses an unfilled denylist slot), so a
 *   revocation endpoint never answers 200 with nothing behind it;
 * - the revocation router, handed no denylist and no declaration, answers
 *   `unsupported_token_type`, never a 200 that means nothing.
 *
 * Accepts `unknown` because its callers in `packages/oauth` read through their
 * own config shapes, which may lack the key.
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
 * Composes a config schema by intersecting module schemas with
 * `CoreConfigSchema`.
 *
 * @deprecated Boot parses the configuration once with core's transitional base,
 * then each module's `configSchema` over the base's output, and refuses outputs
 * that disagree. An intersection parses every schema over the raw input, so a
 * module's schema refuses the environment strings core's schema coerces. Kept
 * for callers that still compose a schema of their own.
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
		// Whether this federation's upstream IdP's `amr` counts (MFA ADR): it is
		// recorded in the session's `amr` beside `fed`, stamped on tokens and
		// matched for `acr`. Absent is `false`: the values are kept apart
		// (`authentication.upstreamAmr`). Beside `enabled` in both shapes, never
		// inside a type's own section.
		trustUpstreamAmr: coerceBooleanFromEnv.optional(),
	})
	.passthrough();

/**
 * The sections core mirrors for other packages' modules. This object strips
 * undeclared keys, so a section parsed through `AppConfigSchema` survives only
 * if declared here. Boot itself parses once, with these sections optional in its
 * transitional base (`TransitionalConfigSchema`); each mirror stays for the
 * coercions and checks it applies, validated whenever the configuration carries
 * it, until its package owns the section. Mirrors are presence and shape only:
 * bounds and defaults stay with the owning package. The modules owning `cors`
 * and `refreshTokenFamilyStore.redis` parse their sections with the
 * declarations here until they have schemas of their own.
 */
export const fullSectionsSchema = z.object({
	// The federation-grants section (see the federation-grants ADR). The bundled
	// Redis grant store reads it too and is installed whether or not the routes
	// are, so losing the block would silently drop the operator's encryption
	// keys and lifetime bound. Bounds live where the values are used
	// (`assertFederationGrantRetrievalLimits`, the store's constructor);
	// defaults in `config/reference.conf`.
	federationGrants: z
		.object({
			enabled: coerceBooleanFromEnv.optional(),
			// Seconds. A new grant's lifetime, and the most an operator permits;
			// the code's one-year ceiling still applies above it.
			defaultExpiresIn: durationFromEnv(z.number().int().positive()).optional(),
			maxExpiresIn: durationFromEnv(z.number().int().positive()).optional(),
			// Seconds. The retrieval's timings.
			refreshBuffer: durationFromEnv(z.number().int().nonnegative()).optional(),
			ineligibleRetryAfter: durationFromEnv(z.number().int().positive()).optional(),
			refreshFailureBackoff: durationFromEnv(z.number().int().nonnegative()).optional(),
			// Milliseconds, as the limits they become are.
			upstreamTimeoutMs: durationFromEnv(z.number().int().positive()).optional(),
			upstreamHardTimeoutMs: durationFromEnv(z.number().int().positive()).optional(),
			refreshLockTtlMs: durationFromEnv(z.number().int().positive()).optional(),
			lockWaitMs: durationFromEnv(z.number().int().nonnegative()).optional(),
			persistRetryBudgetMs: durationFromEnv(z.number().int().positive()).optional(),
			// Seconds. How long a record answers past the end of what it was
			// authorized for; zero keeps no tombstones. At most one year: past the
			// Date range it is a deadline no store can keep, and stores refuse it.
			tombstoneRetention: durationFromEnv(
				z.number().int().nonnegative().max(MAX_DURATION_SECONDS),
			).optional(),
			// Whether a subject-wide revocation may be asked to leave this
			// subject's established grants standing. An allowance, not an
			// instruction: the caller must ask, the request and the outcome are
			// both reported, and boot refuses it with an adapter that cannot stamp
			// the two boundaries separately.
			allowKeepOnSubjectRevocation: coerceBooleanFromEnv.optional(),
			// Whether the connect callback refuses an upstream account already
			// linked to another local user, which needs
			// `UserRepository.findSubjectByFederatedIdentity`. "required", the
			// default, refuses to boot without it; "unsupported" records that this
			// deployment does not make that check.
			identityLookup: z.enum(["required", "unsupported"]).optional(),
			// The deployment's consent page for grants. No default: enabling the
			// feature states that such a page exists, and boot refuses it without
			// one. A path, or an absolute URL on the provider's origin.
			consent: z.object({ url: z.string().min(1).optional() }).optional(),
			// The credential envelope's key ring. The first key seals; every
			// listed key opens, so a key stays in the ring for as long as a paused
			// grant may live.
			encryptionMode: z.enum(["required", "allow-plaintext"]).optional(),
			encryptionKeys: z
				.array(z.object({ id: z.string().min(1), key: z.string().min(1) }))
				.optional(),
			// What a grant may be for. An empty map is valid: removing the last
			// connection must remain an operable change.
			connections: z
				.record(
					z.string().min(1),
					z.object({
						federation: z.string().min(1),
						scopes: z.array(z.string().min(1)).min(1),
						resource: z.string().min(1).optional(),
						// No default for either: a guessed access-token maximum
						// invents a residual-access policy, and a guessed boundary
						// silently shares one.
						boundary: z.string().min(1),
						maxAccessTokenLifetime: durationFromEnv(z.number().int().positive()),
						allowScopeSubsets: coerceBooleanFromEnv.optional(),
						authorizationParams: z.record(z.string(), z.string()).optional(),
						callbackURL: z.string().min(1).optional(),
						// Verified id_token claims handed to the Store beside the
						// subject for the linked-account check. Names only; the
						// package checks them.
						identityClaims: z.array(z.string()).optional(),
					}),
				)
				.optional(),
		})
		.optional(),
	session: z
		.object({
			// Signs the cookie that is the authenticated session, so guessing it
			// forges logins: held to the same 256-bit floor as the JWT signing
			// secret. It goes straight into express-session, so this schema is the
			// only place to check it.
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
			// Positive and bounded: a `maxAge` of 0 (an exported-but-empty
			// SESSION_MAX_AGE) makes express-session emit an already-expired cookie,
			// which looks like a login outage with nothing in the logs.
			maxAge: z.coerce.number().int().positive().max(MAX_DURATION_MS),
			// `SESSION_SECURE=false` (plain-HTTP local runs, the umbrella E2E)
			// arrives as a string, and must not depend on the hocon bridge happening
			// to reach this leaf.
			secure: coerceBooleanFromEnv,
			sameSite: z.enum(["lax", "none", "strict"]),
			domain: z.string().nullable(),
			/**
			 * The exact URLs `POST /session/login` may accept as `redirect_to`,
			 * matched after `new URL(x).href` normalization, with no wildcard or
			 * prefix form. Optional because absence fails closed: a missing key
			 * refuses the redirect, naming this path, rather than opening one.
			 * Validated where the router is built (`@o3co/auth-provider-session`),
			 * because the rule also narrows entries against `session.domain`.
			 */
			redirectAllowlist: z.array(z.string()).optional(),
			/**
			 * CSRF policy for the state-changing session routes. Optional: every
			 * value has a code-side default, so a hand-built config need not
			 * restate it.
			 *
			 * `trustedOrigins` is not `cors.allowedOrigins`: "may this origin read
			 * my responses" and "may it make me change state" are separate
			 * questions. List a login UI served from another origin here,
			 * explicitly. The same list decides where an account-link start
			 * (`?link=1`) may be navigated from.
			 */
			csrf: z
				.object({
					trustedOrigins: z.array(z.string()),
					// A positive integer: the value is stringified into the CSRF token
					// as its expiry, so 0 (an empty SESSION_CSRF_TTL_SECONDS through
					// `z.coerce.number()`), a negative or a fractional value silently
					// makes every token expired or unverifiable at issue. The ceiling
					// is policy: a token meant to outlive an open login form must not
					// become a long-lived bearer value in a JS-readable cookie. It
					// restates `MAX_CSRF_TTL_SECONDS` from
					// `@o3co/auth-provider-session`'s `csrf.mts` (session depends on
					// core, not the reverse); a test there pins the two together.
					ttlSeconds: z.coerce.number().int().positive().max(86_400),
				})
				.optional(),
			storage: z
				.object({
					type: z.string(),
					// Per-type options for `storage.type = "redis"` (the shipped
					// default): sessionStoreModule reads this block as `storageSlice`
					// and spreads `storageSlice[storageSlice.type]` into the store
					// factory — see packages/session/src/modules/sessionStoreModule.mts.
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
			// Browsers refuse to store a `SameSite=None` cookie that is not
			// `Secure`, so the combination fails on the client with no server-side
			// signal.
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
	 * Rate limits for session routes (`/session/login` brute-force protection).
	 * `windowMs` is milliseconds, the `express-rate-limit` shape. The login guard
	 * runs on the shared `rateLimiter` component, keyed `login:ip:<ip>`; these
	 * values stay its source of truth, which the session module contributes as
	 * the `login` budget, in whole seconds, for every limiter to read.
	 *
	 * OAuth endpoint limits (`/token`, `/authorize`) are separate: the
	 * `rateLimiter` slot's modules take them under `memoryRateLimiter.*` /
	 * `redisRateLimiter.*` in `windowSeconds` (`ratelimit/types.mts`).
	 */
	rateLimit: z.object({
		login: rateLimitSchema,
		// The outage policy `redisRateLimiterModule` answers for the limiter it
		// builds; the guard applies the wired limiter's own. The default lives in
		// `reference.conf`: `"closed"` answers 503 and logs. `"open"`
		// (`RATE_LIMIT_FAIL_MODE=open`) lets traffic through and still logs at
		// error, so the outage is visible even with the audit sink down.
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
		// Required: `oauthModule` needs it at boot, so consumers need no null
		// guard. Default `/login` lives in HOCON.
		login: z.object({ url: z.string() }),
		// The deployment-owned consent page for non-first-party clients, like
		// `login`. Default `/consent` from HOCON: the deployment's page, not the
		// `/oauth/consent` JSON API it calls.
		consent: z.object({ url: z.string() }).optional(),
		// The deployment's step-up page (`/mfa` by default, from HOCON). The MFA
		// package's `mfa` requirement registers it, so its `step_up` verdicts
		// send a browser there.
		mfa: z.object({ url: z.string() }).optional(),
	}),
	cors: z.object({
		/**
		 * The browser origins allowed to read the token, userinfo, revocation and
		 * discovery/JWKS responses. Empty (the default) means CORS is off and no
		 * middleware is mounted.
		 *
		 * Matching is exact string equality against `Origin`, so entries are
		 * validated at boot with `../net/origin`: `https://app.example.com/` (a
		 * trailing slash) would otherwise admit nobody, silently. Accepts a list
		 * or one comma-separated string (`${?CORS_ALLOWED_ORIGINS}`; the hocon
		 * bridge cannot coerce to an array), and `null` reads as no list. Any
		 * other shape is refused by path rather than silently turning CORS off.
		 * This list confers no CSRF trust: see `session.csrf.trustedOrigins`.
		 */
		allowedOrigins: z
			.preprocess(
				// Normalisation is shared with `assembleApp`'s mount site
				// (`net/origin.mts`), so the two cannot disagree. A shape neither
				// reads is refused here; the mount site only warns
				// (`cors_allowed_origins_unreadable`).
				(raw, ctx) => {
					if (raw === undefined) return raw;
					if (raw !== null && typeof raw !== "string" && !Array.isArray(raw)) {
						ctx.addIssue({
							code: z.ZodIssueCode.custom,
							message: `cors.allowedOrigins must be a list of origins, or one comma-separated string of them (CORS_ALLOWED_ORIGINS); got ${typeof raw === "object" ? "an object" : `a ${typeof raw}`}`,
						});
						return raw;
					}
					return normalizeAllowedOrigins(raw);
				},
				z.array(z.string()),
			)
			.superRefine((value, ctx) => {
				value.forEach((entry, index) => {
					const rejection = checkSerializedOrigin(entry);
					if (rejection !== null) {
						ctx.addIssue({
							code: z.ZodIssueCode.custom,
							message: `cors.allowedOrigins[${index}] ${describeSerializedOriginRejection(rejection)}`,
							path: [index],
						});
					}
				});
			}),
	}),
	// The WebAuthn deployer section, which a composition root's bootstrap
	// module parses with `webauthnConfigSchema`; lost here, the bootstrap fails
	// on a missing `rpId` instead of reading the operator's. Presence-only:
	// `webauthnConfigSchema` owns the constraints (the origin allowlist's
	// no-wildcard / secure-scheme rules) and the package's `reference.conf` the
	// defaults.
	webauthn: z
		.object({
			rpId: z.string().optional(),
			rpName: z.string().optional(),
			// A list in a config file, a single string from `${?WEBAUTHN_ORIGIN}`.
			// Both spellings reach `webauthnConfigSchema`, which is where the
			// shape is decided; narrowing to an array here would fail the env
			// spelling at the wrong layer, with the wrong message.
			origin: z.union([z.string(), z.array(z.string())]).optional(),
			// The origins this RP may be framed by; the same two spellings as
			// `origin`, for the same reason.
			topOrigin: z.union([z.string(), z.array(z.string())]).optional(),
			challengeTtlMs: z.coerce.number().int().positive().optional(),
			attestationPreference: z.enum(["none", "indirect", "direct", "enterprise"]).optional(),
			userVerification: z.enum(["required", "preferred", "discouraged"]).optional(),
			allowCredentialsForKnownUser: coerceBooleanFromEnv.optional(),
			rateLimit: z
				.object({
					authenticationOptions: rateLimitSpecSchema.optional(),
				})
				.optional(),
		})
		.optional(),
	// Where security-relevant audit events go. `type` selects a builder in the
	// composition root's `AuditSinkFactory`, so it is an open string and
	// sub-keys pass through: an out-of-tree sink needs no schema change here
	// (`registerBuiltinAuditSinks` ships `console`). Core reads one value:
	// `type = "none"`, which the declared-absence guard
	// (AUDIT_SINK_ABSENCE_POLICY) takes as running sink-less on purpose; the
	// standalone registers no "none" builder, so there it still fails boot. The
	// safe default (a sink, never "none") is the composition root's job, and
	// the literal lives in `reference.conf`.
	audit: z
		.object({
			sink: z
				.object({
					type: z.string(),
				})
				.passthrough(),
		})
		.optional(),
	// Connection config for the standalone refresh-token-family client; defaults
	// in HOCON. Module-internal config (`keyPrefix`, `casRetryLimit`) is on the
	// separate top-level key `redisRefreshTokenFamilyStore`.
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
	// Adapter for the rate limiter, which serves both the OAuth endpoints and
	// `/session/login`, so `"redis"` is what makes either safe across replicas.
	// Default `"memory"` in HOCON. `rateLimit.login` still configures the login
	// window and limit, which the session module contributes as the `login`
	// budget.
	rateLimiter: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// Module-internal config for `memoryRateLimiterModule`, kept for its
	// coercions and bounds. Defaults live in HOCON.
	memoryRateLimiter: z
		.object({
			limits: z.record(z.string(), rateLimitSpecSchema).optional(),
			defaultLimit: rateLimitSpecSchema.optional(),
			maxBuckets: z.coerce.number().int().positive().optional(),
		})
		.optional(),
	// The same section for the Redis adapter, which multi-replica deployments
	// run. Lost, `redisRateLimiterModule.configSchema` defaults the whole object
	// to 60 requests / 60 s in place of the operator's per-endpoint budgets.
	// Presence-only; defaults in `reference.conf` and the module.
	redisRateLimiter: z
		.object({
			limits: z.record(z.string(), rateLimitSpecSchema).optional(),
			defaultLimit: rateLimitSpecSchema.optional(),
		})
		.optional(),
	// Adapter for the four user-session stores (`userSessionStore`,
	// `sessionRPRegistry`, `sessionFamilyIndex`, `sessionFederationIndex`).
	// Multi-replica deployments MUST use `"redis"`: memory loses session state
	// on restart and across replicas. Top-level, not under `session.*`, which
	// is the express-session cookie configuration.
	userSessionStores: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// Adapter for the federation token store (upstream IdP tokens held for a
	// session); default `"memory"` in HOCON. Memory forks per replica and its
	// module declares `replicaSafety`, so `core.deployment.mode = "multi"` refuses it
	// by name. `"redis"` mounts `redisFederationTokenStoreModule`, configured
	// under `redisFederationTokenStore`.
	federationTokenStore: z
		.object({
			type: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// The two adapter switches for federation grants. The grant store and the
	// intent store are installed independently: grants in Redis with
	// acquisition in memory is a supported single-replica shape (a restart
	// loses only flows in progress). Both memory modules declare
	// `replicaSafety` and are refused by name under `core.deployment.mode = "multi"`;
	// a Redis grant store beside a memory subject revocation is refused by the
	// routes module. Defaults in `reference.conf`.
	federationGrantStore: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	federationGrantIntentStore: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// Which store keeps enrolled MFA factors, and which keeps MFA transactions
	// and the lock state (MFA ADR); read by a composition root that picks its
	// MFA stores by name. The factor store may be kept in the Store; a
	// transaction is verification state and has no Store variant. Defaults in
	// `reference.conf`.
	mfaFactorStore: z
		.object({
			adapter: z.enum(["memory", "redis", "store"]).optional(),
		})
		.optional(),
	mfaTransactionStore: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
			// The memory store's cap, read by `memoryMfaTransactionStoreModule`
			// the way `challengeStore.memory.maxEntries` is read. Absent: the
			// adapter's default.
			memory: z.object({ maxEntries: z.unknown().optional() }).optional(),
		})
		.optional(),
	// Module-internal config for `redisMfaFactorStoreModule` and
	// `redisMfaTransactionStoreModule`. Presence-only; the defaults (`mfaf:`,
	// `mfat:`) live in `reference.conf` and the modules, which refuse a prefix
	// with a brace.
	redisMfaFactorStore: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	redisMfaTransactionStore: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// This adapter's own layout: where a grant's keys live and how far past a
	// horizon the subject index keeps a member. What a grant may be is
	// `federationGrants` above.
	redisFederationGrantStore: z
		.object({
			keyPrefix: z.string().optional(),
			// One year at most, as every duration here; see tombstoneRetention.
			listingAllowanceMs: z.coerce.number().int().nonnegative().max(MAX_DURATION_MS).optional(),
		})
		.optional(),
	// Module-internal config for `redisFederationTokenStoreModule`, including
	// the encryption key the store cannot start without. Presence-only;
	// defaults in `reference.conf` and the module.
	redisFederationTokenStore: z
		.object({
			keyPrefix: z.string().optional(),
			ttl: z.coerce.number().int().positive().optional(),
			encryptionMode: z.enum(["required", "allow-plaintext"]).optional(),
			encryptionKey: z.string().optional(),
			// An exported-but-empty variable reads as `false`, which turns off
			// this migration safety net (default `true`): set the variable to
			// `true` or `false`, never empty.
			scanFallback: coerceBooleanFromEnv.optional(),
		})
		.optional(),
	// Module-internal config for `redisDeviceCodeStoreModule`. Presence-only;
	// the default lives in the module.
	redisDeviceCodeStore: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// Adapter for the RFC 7009 access-token denylist; default `"memory"` in
	// HOCON. Memory forks per replica (a revocation on one leaves the token
	// working on the others), so `core-access-token-denylist-memory` is in the
	// replica-safety guard's refused set under `core.deployment.mode = "multi"`.
	accessTokenDenylist: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
		})
		.optional(),
	// Backend for the replay seen-set: the single-use `jti` record behind
	// `private_key_jwt` client authentication (and the WebAuthn challenge
	// ceremony when installed). `core-replay-seen-set-memory` is in the
	// replica-safety guard's refused set: a captured assertion would replay
	// once per replica.
	replaySeenSet: z
		.object({
			adapter: z.enum(["memory", "redis"]).optional(),
			// The memory seen-set's cap, read by `memoryReplaySeenSetModule`,
			// which refuses at boot anything but a positive whole number (a digit
			// string from an environment variable is taken). Absent: the
			// adapter's default.
			memory: z.object({ maxEntries: z.unknown().optional() }).optional(),
		})
		.optional(),
	// The memory challenge store's cap, read by `memoryChallengeStoreModule`,
	// the same way as `replaySeenSet.memory.maxEntries` above.
	challengeStore: z
		.object({
			memory: z.object({ maxEntries: z.unknown().optional() }).optional(),
		})
		.optional(),
	// Where consent to a non-first-party client is recorded. `"none"` (the HOCON
	// default) wires nothing, so such clients are refused; `"memory"` forks per
	// replica and is refused under `core.deployment.mode = "multi"`; `"redis"` shares
	// consent records and parked requests across replicas.
	consentStore: z
		.object({
			adapter: z.enum(["none", "memory", "redis"]).optional(),
		})
		.optional(),
	// Module-internal config for `redisConsentStoreModule`. Presence-only;
	// defaults in `reference.conf` and the module.
	redisConsentStore: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// Module-internal config for `redisAccessTokenDenylistModule`.
	// Presence-only; defaults in `reference.conf` and the module.
	redisAccessTokenDenylist: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// Module-internal config for `redisSessionStoresModule` (the bundled Redis
	// user-session namespace). Presence-only.
	redisSessionStores: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	// Module-internal config for `redisRefreshTokenFamilyStoreModule`
	// (`REFRESH_TOKEN_FAMILY_STORE_KEY_PREFIX` / `..._CAS_RETRY_LIMIT`).
	// Presence-only: the module's `configSchema` owns shape and defaults, with
	// `reference.conf`.
	redisRefreshTokenFamilyStore: z
		.object({
			keyPrefix: z.string().optional(),
			casRetryLimit: z.coerce.number().optional(),
		})
		.optional(),
	// Module-internal config for `redisCodeRepositoryModule`
	// (`CLIENT_CODE_KEY_PREFIX` / `CLIENT_CODE_DEFAULT_EXPIRES_IN`).
	// Presence-only; defaults in `reference.conf`.
	redisCodeRepository: z
		.object({
			keyPrefix: z.string().optional(),
			// The Redis PX TTL, in seconds, for authorization codes. A positive
			// integer so a bad env override fails boot instead of erroring on
			// every Redis call; the module schema and the `RedisCodeRepository`
			// constructor check it again.
			defaultExpiresIn: z.coerce.number().int().positive().optional(),
		})
		.optional(),
	// Presence-only; defaults in the modules.
	redisChallengeStore: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
	redisReplaySeenSet: z
		.object({
			keyPrefix: z.string().optional(),
		})
		.optional(),
});

/**
 * Full application config schema including all optional module sections. A
 * plain ZodObject (via `.extend`) so consumers can read `.shape` and the
 * ts.hocon zod coercion can traverse it.
 *
 * @deprecated A composition root hands `createApp` the configuration it
 * resolved, and boot parses it once with each loaded module's own schema;
 * parsing with this schema first strips every section it does not declare.
 * Read what the root needs before it knows its modules with
 * `readTransitionalConfig`. The `AppConfig` type stays.
 */
export const AppConfigSchema = CoreConfigSchema.extend(fullSectionsSchema.shape);

export type AppConfig = z.infer<typeof AppConfigSchema>;
