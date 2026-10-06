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
 * Zod schemas for core's own configuration, `core`, and the readers core keeps
 * for keys of the oauth module's section it reads by path (the token
 * lifetimes, the access-token revocation mode). The schemas are a pure type
 * contract: the shape required at the boundary, not defaults. Defaults live
 * only in a `reference.conf` — core's own sections' in
 * `packages/core/config/reference.conf`, a module's in the one its manifest
 * declares. Tests load through `parseFile` or start from
 * `makeValidCoreConfig` (`@o3co/auth-provider-core/testing`). See ADR
 * 2026-04-30.
 */
import { z } from "zod";

import { OutboundSectionSchema } from "../net/outbound-policy.mjs";
import { MAX_DURATION_SECONDS } from "./durations.mjs";
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

/**
 * `oauth.accessToken` once the oauth module's section schema has parsed it.
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
 * a configuration built by hand that never met the oauth module's schema. Values are
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
	| { readonly ok: false; readonly message: string };

/**
 * The lifetime rules {@link resolveAccessTokenLifetime} holds a configuration
 * to; the oauth module's section schema holds `oauth.accessToken` to the same
 * rules, in the same words. `defaultExpiresIn` wins over the deprecated `expiresIn` whenever set, and a
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
 * The oauth module's section schema enforces the same rules at boot; they are
 * repeated for a configuration no such schema parsed — one built by hand, or
 * one whose `oauth {}` no loaded module owns — so a bad or missing value fails
 * when the grant is built rather than after a request's single-use credential
 * is spent. The alias is
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
 * a configuration built by hand that never met the oauth module's schema. The value is
 * `unknown` because the resolver validates it rather than trusting a type.
 */
export interface RefreshTokenLifetimeSource {
	readonly oauth?: { readonly refreshToken?: { readonly expiresIn?: unknown } };
}

/**
 * The refresh-token lifetime a deployment configured, in seconds
 * (`oauth.refreshToken.expiresIn`), and the one reader of that key: every grant
 * minting a refresh token reads it when built, as does the subject-revocation
 * horizon. The oauth module's section schema refuses bad values at boot; the
 * check is repeated for a configuration no such schema parsed — one built by
 * hand, or one whose `oauth {}` no loaded module owns — so a grant fails when
 * built, not after spending a code or challenge or signing a refresh token
 * with no `exp`.
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
 * Core's own configuration: the one section core declares, `core`. Every
 * other top-level section is a module's, parsed by that module's schema when
 * it is loaded (`oauth {}` is the oauth module's), and declared by nothing
 * here: core reads none of them through this schema.
 */
export const CoreConfigSchema = z.object({
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
 * The type of the `config` slot: the configuration as boot's composed parse
 * leaves it. Core's own sections are parsed by `CoreConfigSchema`; every other
 * top-level section is a loaded module's, parsed by that module's own schema
 * and read through its `deps.section`, or one nothing loaded reads. Core
 * declares no type for them, so each reads as `unknown` here.
 */
export type AppConfig = CoreConfig & Readonly<Record<string, unknown>>;
