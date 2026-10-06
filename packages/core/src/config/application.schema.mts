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

import { checkCanonicalIssuer, describeIssuerRejection } from "../issuer/canonical.mjs";
import { OutboundSectionSchema } from "../net/outbound-policy.mjs";
import { checkAcrValueName } from "./acr-values.mjs";
import { MAX_DURATION_SECONDS } from "./durations.mjs";
import { type RemovedKey, unreadSection, withRemovedKeys } from "./removed-keys.mjs";
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
			"The one-time migration flag for the /authorize first-party invariant is " +
			"gone: a client whose registration does not carry `firstParty: true` is now always " +
			"refused, whatever this key is set to. Mark every client you operate with " +
			"`firstParty: true` (only ones you would trust to receive a user's identity without " +
			"the user being asked), then delete this key and the " +
			"OAUTH_AUTHORIZE_ALLOW_UNMARKED_CLIENTS environment variable.",
	},
];

/**
 * A whole number read strictly: a number, or a string of decimal digits (a
 * whole number) as an environment variable arrives, whitespace around the
 * digits allowed. Not `z.coerce.number()`, which reads `""`, `null` and `[]`
 * as 0, `true` as 1 and `"1e3"` as 1000: a malformed value would be
 * normalised instead of failing boot naming the key. `bounds` decide every
 * other rule.
 */
export const wholeNumberFromEnv = (bounds: z.ZodNumber) =>
	environmentCoercer(
		z.preprocess((value) => {
			if (typeof value === "number") return value;
			if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
			// Handed through unchanged, and refused by `bounds` with a message that
			// names what is acceptable.
			return value;
		}, bounds),
	);

/**
 * {@link wholeNumberFromEnv} held to `min`, and to `max` when given, every
 * refusal carrying one message that names the range and the form. The reader
 * for a number setting that needs no message of its own.
 */
export const wholeNumberInRangeFromEnv = (min: number, max?: number) => {
	const error =
		max === undefined
			? `must be a whole number of at least ${min}, in decimal digits`
			: `must be a whole number from ${min} to ${max}, in decimal digits`;
	const bounds = z.number({ error }).int({ error }).min(min, { error });
	return wholeNumberFromEnv(max === undefined ? bounds : bounds.max(max, { error }));
};

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
	// Presence-only: the path the key-store module's section moved from, kept
	// so a root that parses with `AppConfigSchema` before boot still hands it
	// to the relocation refusal. Nothing reads it.
	signingKey: z.unknown().optional(),
	// When true, the JWT verifier accepts tokens with no `typ` header and warns.
	// No schema default: `reference.conf` ships `false` (a typ-less token is a
	// misconfiguration or downgrade signal); `OAUTH_JWT_LEGACY_TYP_ACCEPT=true`
	// is a migration override. `coerceBooleanFromEnv` because this section sits
	// behind `z.preprocess`, which the hocon bridge does not coerce through.
	legacyTypAccept: coerceBooleanFromEnv.optional(),
	// Presence-only: the JWKS module's old paths, kept so a root that parses
	// with `AppConfigSchema` before boot still hands them to the relocation
	// refusal. Nothing reads them.
	jwksPath: z.unknown().optional(),
	jwksCacheMaxAge: z.unknown().optional(),
});

/**
 * Detects legacy flat `oauth.jwt.*` fields on the raw input: Zod strips unknown
 * keys before `superRefine` runs, so only `z.preprocess` can see them.
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
					`Migrate to the key store's section: key-store.local.<field>. ` +
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

/** A lifetime in whole seconds, positive and bounded. */
const lifetimeSecondsSchema = wholeNumberInRangeFromEnv(1, MAX_DURATION_SECONDS);

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
	// Shape only, with no default: the oauth package owns the key and its
	// default. The enum keeps any other string from reaching the refresh grant.
	unknownFamilyPolicy: z.enum(["accept", "reject"]).optional(),
	// Refresh tokens lacking `jti` or `family_id` while family rotation is wired
	// are rejected. Shape only, with no default: the oauth package owns the key
	// and its default. `"reject"` is the only value, so a stale
	// `accept-with-warning` fails boot on this field.
	legacyRtPolicy: z.enum(["reject"]).optional(),
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
 * `oauth.authorize.acrValues`: each key an acr value a request can name
 * (`checkAcrValueName`), refused under the key otherwise, so no deployment
 * advertises one `/authorize` can never be asked for. The keys are judged
 * whenever the table is a record, beside any entry refused for its value, so
 * one boot names every key to fix.
 */
const acrValuesSchema = z.record(z.string().min(1), acrRequirementSchema).superRefine(
	(table, ctx) => {
		for (const name of Object.keys(table)) {
			const refusal = checkAcrValueName(name);
			if (refusal !== null) ctx.addIssue({ code: "custom", message: refusal, path: [name] });
		}
	},
	{
		when: ({ value }) => typeof value === "object" && value !== null && !Array.isArray(value),
	},
);

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
			acrValues: acrValuesSchema.optional(),
		})
		.optional(),
);

/**
 * Ceiling for a `trust proxy` hop count: a typo guard, not a policy. A large
 * number meant as "trust everything" would silently grant the blanket trust
 * `true` states openly. Exported so the `httpSettings` contract suite, and the
 * module that parses a composition's HTTP settings, hold the value to it.
 */
export const MAX_TRUST_PROXY_HOPS = 255;

/** Why an entry without a type, or with an empty or blank one, is refused. */
const FEDERATION_TYPE_REQUIRED =
	"every federation names its type: the federationTypes key of the installed module that handles it";

/**
 * One federation in `core.federations`. Core owns `enabled`, `type`,
 * `trustUpstreamAmr`, `callbackMeetsFreshness` and `callbackURL`, and boot
 * strips them before the schema of the entry's type sees the entry; every
 * other key is the type's, kept as written here, beside them: an entry is
 * flat. Every entry names its `type`, enabled or not: the module registering
 * that type under `federationTypes` is the one that handles it.
 * `callbackURL` is not declared here: boot requires it of an entry it
 * dispatches by type.
 */
const federationEntrySchema = z
	.object({
		enabled: coerceBooleanFromEnv,
		type: z
			.string({ error: FEDERATION_TYPE_REQUIRED })
			.regex(/\S/, { error: FEDERATION_TYPE_REQUIRED }),
		// Whether this federation's upstream IdP's `amr` counts (MFA ADR): it is
		// recorded in the session's `amr` beside `fed`, stamped on tokens and
		// matched for `acr`. Absent is `false`: the values are kept apart
		// (`authentication.upstreamAmr`).
		trustUpstreamAmr: coerceBooleanFromEnv.optional(),
		// Whether this federation's callback alone meets a freshness ask
		// (`prompt=login`, `max_age`) when the upstream shows no `auth_time`.
		// Read by `federationCallbackMeetsFreshness`, which supplies the default.
		callbackMeetsFreshness: coerceBooleanFromEnv.optional(),
	})
	.passthrough();

/**
 * Minimal always-required config for the auth provider core.
 * Token-only deployments (no session, no federation) only need these sections.
 */
export const CoreConfigSchema = z.object({
	oauth: z.object({
		jwt: jwtSchema,
		// The access-token lifetime: `defaultExpiresIn`, `maxExpiresIn`, and the
		// deprecated `expiresIn` alias. See `accessTokenSchema` and
		// `resolveAccessTokenLifetime`.
		accessToken: accessTokenSchema,
		refreshToken: refreshTokenSchema,
		// Presence-only: the path the grant switches moved from (each grant's
		// under its module's section, `oauth-session` and
		// `oauth-authorization`), kept so a root that parses with
		// `AppConfigSchema` before boot still hands it to the relocation
		// refusal. Nothing reads it.
		grants: z.unknown().optional(),
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
		// Presence-only: the path the code repository's selection moved from (the
		// composition root's `adapters.codeRepository`). Nothing reads it.
		code: z.unknown().optional(),
		// Presence-only: the paths the device-grant, oauth-token-exchange, mTLS
		// and DPoP modules' sections moved from, kept so a root that parses with
		// `AppConfigSchema` before boot still hands them to the relocation
		// refusal. Nothing reads them.
		deviceAuthorization: z.unknown().optional(),
		tokenExchange: z.unknown().optional(),
		mtls: z.unknown().optional(),
		dpop: z.unknown().optional(),
		// Bounds the OIDC `nonce` at /authorize so a malicious RP cannot exhaust
		// per-request memory or bloat the id_token. Default in HOCON.
		nonce: z
			.object({
				maxLength: wholeNumberInRangeFromEnv(1),
			})
			.optional(),
		// Opt-in RFC 8707 Resource Indicator enforcement; off in reference.conf
		// (`OAUTH_RESOURCE_INDICATOR_ENABLED=true` turns it on).
		resourceIndicator: z
			.object({
				enabled: coerceBooleanFromEnv,
			})
			.optional(),
		// Presence-only: the keys of `oauth {}` the oauth module's own schema
		// declares — the consent page, and the Client ID Metadata Documents —
		// kept so a root that parses with `AppConfigSchema` before boot does not
		// strip them. The module parses them.
		consentPage: z.unknown().optional(),
		clientIdMetadataDocuments: z.unknown().optional(),
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
		// Presence-only: the path core's token-binding settings moved from
		// (`core.tokenBinding`), kept so a root that parses with
		// `AppConfigSchema` before boot still hands it to the relocation
		// refusal. Nothing reads it.
		tokenBinding: z.unknown().optional(),
	}),
	// Core's own section, strict at every level: an unknown key is refused,
	// named and never its value.
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
				.strict()
				.optional(),
			// The requirement names a composition expects (session-admission ADR),
			// compared at the end of boot's stage 4 with what registered, both ways
			// once written. Required whenever a consumer of admission is installed,
			// `[]` allowed, and no default anywhere: every composition states its
			// posture. `secondFactorAuthority`, optional with no default, names the
			// expected requirement boot holds to declaring the second-factor
			// authority.
			sessionRequirements: z
				.object({
					expected: z.array(
						z.string().min(1, {
							error: "core.sessionRequirements.expected names each requirement",
						}),
					),
					secondFactorAuthority: z
						.string({
							error: "core.sessionRequirements.secondFactorAuthority names a requirement",
						})
						.min(1, {
							error: "core.sessionRequirements.secondFactorAuthority names a requirement",
						})
						.optional(),
				})
				.strict()
				.optional(),
			// The settings across every mechanism at core's token-binding
			// extension point (DPoP, mTLS, ...), core's as the point is: read
			// through `resolveTokenBindingSettings` alone, and carried by no
			// module's slot — boot fills core's `tokenBindingSettings` with
			// them. See
			// `packages/core/docs/adr/2026-05-20-token-binding-first-class-abstraction.md`.
			// The slots this composition runs without on purpose, each a slot a
			// module's absence policy names by its key here (`auditSink`): the
			// declared-absence guard reads the list, and no variable sets it.
			declaredAbsent: z
				.array(z.string().min(1, { error: "core.declaredAbsent names each slot" }), {
					error: "core.declaredAbsent is a list of slot names",
				})
				.optional(),
			// The federations this deployment runs, keyed by the name each is
			// reached at (`/session/oauth/federation/<name>`): one map, so a name
			// is unique across every type. Read through `federationsOf`.
			federations: z.record(z.string(), federationEntrySchema).optional(),
			// The destination policy of every fetch of a URL a client
			// registration or a request supplies; its shape is the policy's own
			// (`net/outbound-policy.mts`).
			outbound: OutboundSectionSchema.optional(),
			// The session lifecycle's sweep of pending closes: every 60 seconds
			// unless written, 0 turning it off. Read by `readSessionLifecycleSweepIntervalMs` alone, as
			// core's numbers are read.
			sessionLifecycle: z
				.object({ sweepIntervalSeconds: z.unknown().optional() })
				.strict()
				.optional(),
			tokenBinding: z
				.object({
					// How `tokenBindingMw` arbitrates when several mechanisms succeed
					// on one request.
					dispatchPolicy: z.enum(["intent-explicit", "strict-mutual-exclusion"]),
					// Bind a confidential client's refresh token to the presented DPoP
					// key or client certificate, as is always done for public clients.
					// RFC 9449 §5 and RFC 8705 §7.1 neither require nor forbid it: a
					// confidential client authenticates on refresh, and this
					// implementation refuses an unauthenticated caller and an RT whose
					// `azp` is not that client. Hardening for deployments whose key is
					// better protected than the client secret (HSM or TPM vs an env
					// var). Off by default: a bound RT pins the client to one key for
					// its whole lifetime, so rotating mid-lifetime breaks refresh.
					bindConfidentialClientRefreshTokens: coerceBooleanFromEnv.optional(),
				})
				.strict()
				.optional(),
		})
		.strict()
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
 * then each module's section at its name over the base's output. An
 * intersection parses every schema over the raw input, so a module's schema
 * refuses the environment strings core's schema coerces. Kept for callers
 * that still compose a schema of their own.
 */
export function composeConfigSchema(moduleSchemas: z.ZodObject<z.ZodRawShape>[]): z.ZodType {
	let schema: z.ZodType = CoreConfigSchema;
	for (const moduleSchema of moduleSchemas) {
		schema = schema.and(moduleSchema);
	}
	return schema;
}

/**
 * The sections core mirrors for other packages' modules. This object strips
 * undeclared keys, so a section parsed through `AppConfigSchema` survives only
 * if declared here. Boot itself parses once, with these sections optional in its
 * transitional base (`TransitionalConfigSchema`); each mirror stays for the
 * coercions and checks it applies, validated whenever the configuration carries
 * it, until its package owns the section. Mirrors are presence and shape only:
 * bounds and defaults stay with the owning package.
 */
export const fullSectionsSchema = z.object({
	// Presence-only: the paths core's own settings moved from, kept so a root
	// that parses with `AppConfigSchema` before boot still hands them to the
	// relocation refusal, which refuses them before boot's parse. Nothing reads
	// them.
	deployment: z.unknown().optional(),
	sessionRequirements: z.unknown().optional(),
	// Presence-only: the path the federation-grants section, and the grant
	// stores' own keys, moved from.
	federationGrants: z.unknown().optional(),
	// The federation-grants module's section, parsed by its module. Mirrored
	// for the one key a composition root reads before it knows its modules,
	// `enabled`; every other key is kept as written.
	"federation-grants": z
		.object({ enabled: coerceBooleanFromEnv.optional() })
		.passthrough()
		.optional(),
	// The oauth package's grant modules' sections, each parsed by its module.
	// Mirrored for the keys a composition root reads before it knows its
	// modules — whether each grant is on — kept as written.
	"oauth-session": z.object({ enabled: z.unknown().optional() }).passthrough().optional(),
	"oauth-authorization": z.object({ grants: z.unknown().optional() }).passthrough().optional(),
	// Presence-only: the session module's section, `session`, which its module
	// parses, and under it the paths the session store's keys moved from; and
	// `rateLimit`, where the login's budget moved from. Kept so a root that
	// parses with `AppConfigSchema` before boot still hands them to the
	// relocation refusal. Core reads `rateLimit.failMode` alone, as written,
	// for boot's `rate_limit_fail_mode_not_applied` warning.
	session: z.unknown().optional(),
	rateLimit: z.unknown().optional(),
	// The session store's section, parsed by its module. Mirrored for the key
	// a composition root may read before boot — the storage — kept as
	// written.
	"session-store": z
		.object({
			storage: z.object({ type: z.unknown().optional() }).passthrough().optional(),
		})
		.passthrough()
		.optional(),
	// Presence-only: the path the federations' map moved from
	// (`core.federations`), kept so a root that parses with `AppConfigSchema`
	// before boot still hands it to the relocation refusal. Nothing reads it.
	federations: z.unknown().optional(),
	// Presence-only: the section the repositories' settings sit in (the
	// standalone template's `repositories` module's), and where the code
	// repositories' moved from. Nothing in core reads it.
	repositories: z.unknown().optional(),
	// Presence-only: the paths the login and consent pages moved from
	// (`session.loginPage.url`, `oauth.consentPage.url`). Nothing reads them.
	endpoints: z.unknown().optional(),
	// Refused whenever present: core reads a composition's CORS origins from
	// the `httpSettings` slot alone. A loaded module that relocates `cors` (the
	// standalone template's `http`) refuses it first, before parse, naming its
	// own path.
	cors: unreadSection(
		"cors",
		"The CORS origins are handed to core in the httpSettings slot (cors.allowedOrigins), by the module that provides the slot; without the slot, no CORS is mounted.",
	),
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
			challengeTtlMs: wholeNumberInRangeFromEnv(1).optional(),
			attestationPreference: z.enum(["none", "indirect", "direct", "enterprise"]).optional(),
			userVerification: z.enum(["required", "preferred", "discouraged"]).optional(),
			// Presence-only: removed keys, kept so a root that parses with
			// `AppConfigSchema` before boot still hands them to the removed-key refusal.
			allowCredentialsForKnownUser: z.unknown().optional(),
			rateLimit: z.unknown().optional(),
		})
		.optional(),
	// Presence-only: the path the audit sink's selection (the composition
	// root's `adapters.auditSink`), its options (the `audit-sink` module's) and
	// its declared absence (`core.declaredAbsent`) moved from.
	audit: z.unknown().optional(),
	// Presence-only: the path the shared Redis connection's settings moved from
	// (`redis-clients`, the standalone template's module's). Nothing reads it.
	refreshTokenFamilyStore: z.unknown().optional(),
	// Presence-only: the paths the adapter selections moved from (the
	// composition root's `adapters`), and the stores' sections moved from with
	// them, kept so a root that parses with `AppConfigSchema` before boot
	// still hands them to the relocation refusal. Nothing reads them.
	rateLimiter: z.unknown().optional(),
	userSessionStores: z.unknown().optional(),
	federationTokenStore: z.unknown().optional(),
	federationGrantStore: z.unknown().optional(),
	federationGrantIntentStore: z.unknown().optional(),
	mfaFactorStore: z.unknown().optional(),
	mfaTransactionStore: z.unknown().optional(),
	accessTokenDenylist: z.unknown().optional(),
	replaySeenSet: z.unknown().optional(),
	challengeStore: z.unknown().optional(),
	consentStore: z.unknown().optional(),
	redisCodeRepository: z.unknown().optional(),
	// Presence-only: the paths the stores' sections moved from, kept so a root
	// that parses with `AppConfigSchema` before boot still hands them to the
	// relocation refusal. Nothing reads them.
	memoryRateLimiter: z.unknown().optional(),
	redisRateLimiter: z.unknown().optional(),
	redisAccessTokenDenylist: z.unknown().optional(),
	redisChallengeStore: z.unknown().optional(),
	redisConsentStore: z.unknown().optional(),
	redisDeviceCodeStore: z.unknown().optional(),
	redisMfaFactorStore: z.unknown().optional(),
	redisMfaTransactionStore: z.unknown().optional(),
	redisRefreshTokenFamilyStore: z.unknown().optional(),
	redisReplaySeenSet: z.unknown().optional(),
	redisSessionStores: z.unknown().optional(),
	redisFederationTokenStore: z.unknown().optional(),
	redisFederationGrantStore: z.unknown().optional(),
	// Presence-only: the stores' own sections, each parsed by its module. A
	// package's `reference.conf` is layered whenever any of its modules is
	// loaded, so it sets these sections while their own module may not be;
	// declared here, they are not named as ignored at boot.
	"core-rate-limiter-memory": z.unknown().optional(),
	"core-federation-grant-store-memory": z.unknown().optional(),
	"redis-access-token-denylist": z.unknown().optional(),
	"redis-challenge-store": z.unknown().optional(),
	"redis-code-repository": z.unknown().optional(),
	"redis-consent-store": z.unknown().optional(),
	"redis-device-code-store": z.unknown().optional(),
	"redis-mfa-factor-store": z.unknown().optional(),
	"redis-mfa-transaction-store": z.unknown().optional(),
	"redis-rate-limiter": z.unknown().optional(),
	"redis-refresh-token-family-store": z.unknown().optional(),
	"redis-replay-seen-set": z.unknown().optional(),
	"redis-session-stores": z.unknown().optional(),
	"redis-federation-token-store": z.unknown().optional(),
	"redis-federation-grant-store": z.unknown().optional(),
	"redis-federation-grant-intent-store": z.unknown().optional(),
	// Presence-only, for the same reason: the WebAuthn second factor's
	// section, parsed by its module, set by the webauthn package's
	// `reference.conf` wherever the grant's module is loaded without it.
	"webauthn-mfa-factor": z.unknown().optional(),
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
