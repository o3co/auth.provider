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
 * The oauth module's own section, `oauth {}`: the schema boot parses it with,
 * and the type the module's factories read it as (`deps.section`).
 *
 * Every object level is strict: a key it does not declare refuses boot, named
 * at its path, instead of being dropped unread. The defaults live in the
 * package's `config/reference.conf`, not here, and each leaf reads the string
 * an environment variable carries.
 *
 * Core declares none of these keys: its schema declares `core` alone, and the
 * section's defaults and variables are this package's alone. The module
 * refuses its removed keys (`oauth.refreshToken.legacyRtPolicy`,
 * `oauth.refreshToken.legacyTokenCompat`, `oauth.authorize.allowUnmarkedClients`)
 * before the schema parses, from its manifest's `relocatedFrom`, and so do the
 * modules other sections moved to for the paths they moved from
 * (`oauth.grants`, `oauth.dpop`, `oauth.jwt.signingKey`, …), while loaded.
 * Here a moved path may only be an empty object or null, which set nothing,
 * and a retired key — `oauth.jwt`'s flat key fields among them — is a key
 * this section does not declare.
 */

import {
	type AccessTokenConfig,
	checkAcrValueName,
	checkCanonicalIssuer,
	coerceBooleanFromEnv,
	describeIssuerRejection,
	isLifetimeSeconds,
	MAX_DURATION_SECONDS,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";

/**
 * A path another module's section moved from: it sets nothing here, so only an
 * empty object — a layer that still carries the old section, emptied — or null,
 * HOCON's way of unsetting an inherited block, is accepted, and a key under it
 * is refused.
 */
const movedAway = z.object({}).strict().nullable().optional();

/** `oauth.jwt`: the canonical issuer and the typ-less-token switch. */
const jwtSchema = z
	.object({
		// Required: the issuer belongs to the deployment, never to a request. An
		// `iss` derived from the Host header is caller-controlled behind a
		// trusted proxy.
		issuer: z.string().superRefine((value, ctx) => {
			const rejection = checkCanonicalIssuer(value);
			if (rejection) {
				ctx.addIssue({
					code: "custom",
					message: `oauth.jwt.issuer ${describeIssuerRejection(rejection)}`,
				});
			}
		}),
		// When true, the JWT verifier accepts a token with no `typ` header, and
		// warns. A migration override; `reference.conf` ships `false`.
		legacyTypAccept: coerceBooleanFromEnv.optional(),
		// The key store's section moved from here.
		signingKey: movedAway,
	})
	.strict();

/** A lifetime in whole seconds, positive and bounded. */
const lifetimeSecondsSchema = wholeNumberInRangeFromEnv(1, MAX_DURATION_SECONDS);

const ACCESS_TOKEN_LIFETIME_KEYS = ["defaultExpiresIn", "maxExpiresIn", "expiresIn"] as const;

/**
 * `oauth.accessToken`. Every key is optional so either spelling of the default
 * can stand alone; the refinement requires one, and refuses a default above
 * the max, by the rules and in the words of core's `resolveAccessTokenLifetime`,
 * which reads the lifetime for every grant. The output mirrors the resolved
 * default onto the deprecated `expiresIn`, idempotently: boot may parse a
 * configuration this level already parsed.
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
	.strict()
	.superRefine((value, ctx) => {
		// A value that failed its own leaf check is already reported by name; a
		// cross-field complaint built on it would only be noise.
		if (
			ACCESS_TOKEN_LIFETIME_KEYS.some(
				(key) => value[key] !== undefined && !isLifetimeSeconds(value[key]),
			)
		) {
			return;
		}
		const configuredDefault = value.defaultExpiresIn;
		const defaultExpiresIn = configuredDefault ?? value.expiresIn;
		if (defaultExpiresIn === undefined) {
			ctx.addIssue({
				code: "custom",
				message:
					"oauth.accessToken.defaultExpiresIn is required (OAUTH_ACCESS_TOKEN_DEFAULT_EXPIRES_IN); the deprecated oauth.accessToken.expiresIn is still read in its place",
				path: ["defaultExpiresIn"],
			});
			return;
		}
		const maxExpiresIn = value.maxExpiresIn ?? defaultExpiresIn;
		if (defaultExpiresIn > maxExpiresIn) {
			const source =
				configuredDefault === undefined
					? ", read from the deprecated oauth.accessToken.expiresIn"
					: "";
			ctx.addIssue({
				code: "custom",
				message: `oauth.accessToken.defaultExpiresIn (${defaultExpiresIn}${source}) must not exceed oauth.accessToken.maxExpiresIn (${maxExpiresIn}): lower the default or raise the max`,
				path: ["maxExpiresIn"],
			});
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

/** `oauth.refreshToken`. */
const refreshTokenSchema = z
	.object({
		// Positive and bounded: the rule `resolveRefreshTokenLifetime` holds a
		// hand-built configuration to.
		expiresIn: lifetimeSecondsSchema,
	})
	.strict();

/**
 * One `oauth.authorize.acrValues` entry: `amr` values a session must all carry,
 * or a list of such lists, any one of which suffices —
 * `"urn:o3co:acr:phr" = [["hwk"], ["swk"]]`. An empty list or alternative is
 * refused: every session would satisfy it.
 */
const acrAlternativeSchema = z.array(z.string().min(1)).min(1);
const acrRequirementSchema = z.union([acrAlternativeSchema, z.array(acrAlternativeSchema).min(1)]);

/**
 * `oauth.authorize.acrValues`: each key an acr value a request can name, held
 * to core's `checkAcrValueName` and refused under the key in its words. The
 * keys are judged whenever the table is a record, beside any entry refused
 * for its value, so one boot names every key to fix.
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

/** `oauth.authorize`: the acr table. */
const authorizeSchema = z
	.object({
		// The Authentication Context Class References this deployment vouches
		// for, each mapped to the RFC 8176 `amr` values that satisfy it.
		// `/authorize` answers `acr_values` from this table alone, and discovery
		// advertises its keys, less the entries nothing installed can satisfy.
		acrValues: acrValuesSchema.optional(),
	})
	.strict()
	.optional();

/**
 * A list an environment variable may carry as one comma-separated string:
 * entries trimmed and empties dropped, so an exported-but-empty variable is
 * `[]`.
 */
const commaList = z.union([z.array(z.string()), z.string()]).transform((value) =>
	Array.isArray(value)
		? value
		: value
				.split(",")
				.map((entry) => entry.trim())
				.filter((entry) => entry.length > 0),
);

export const oauthSectionSchema = z
	.object({
		jwt: jwtSchema,
		// The access-token lifetime: `defaultExpiresIn`, `maxExpiresIn`, and the
		// deprecated `expiresIn` alias.
		accessToken: accessTokenSchema,
		refreshToken: refreshTokenSchema,
		// As an OIDC OP, `/authorize` refuses a request without `openid` unless
		// the operator chose dual OAuth/OIDC mode.
		oidcMode: z.enum(["oidc-required", "dual"]),
		// Require a verified email the Store published before issuing tokens for
		// an end-user subject. The verification flow stays with the Store; this
		// only gates issuance.
		requireEmailVerified: coerceBooleanFromEnv.optional(),
		// Deny-by-absence for each client's `allowedGrantTypes`: on, a client
		// whose registration names no grants gets none. Composes with a grant's
		// own `requiresExplicitGrantAllowlist` to the stricter of the two.
		requireGrantTypeAllowlist: coerceBooleanFromEnv.optional(),
		// `/authorize` refuses a client not marked `firstParty: true`; this level
		// carries the acr table.
		authorize: authorizeSchema,
		// Bounds the OIDC `nonce` at /authorize, so a relying party cannot
		// exhaust per-request memory or bloat the id_token.
		nonce: z
			.object({ maxLength: wholeNumberInRangeFromEnv(1) })
			.strict()
			.optional(),
		// Opt-in RFC 8707 Resource Indicator enforcement.
		resourceIndicator: z.object({ enabled: coerceBooleanFromEnv }).strict().optional(),
		/**
		 * The deployment-owned page a client that is not first-party is sent to
		 * with `?challenge=<id>`: a path or an absolute URL, which may carry a
		 * query of its own. Never empty or blank: such a url would send the browser to
		 * `?challenge=<id>` relative to `/oauth/authorize`, and an exported but
		 * empty variable is a mistake to name, not an unset one to default.
		 */
		consentPage: z
			.object({
				url: z.string().refine((url) => url.trim() !== "", {
					message:
						'oauth.consentPage.url must not be empty or blank: an exported-but-empty OAUTH_CONSENT_PAGE_URL reads as ""; unset it to keep the default, /consent, or set it to the consent page',
				}),
			})
			.strict()
			.optional(),
		/**
		 * A `client_id` that is the https URL of the client's own registration
		 * (draft-ietf-oauth-client-id-metadata-document). Off by default. The
		 * list keys also take a comma-separated string. Every ceiling here is the
		 * operator's: a document says who a client is, never what it may reach.
		 */
		clientIdMetadataDocuments: z
			.object({
				enabled: coerceBooleanFromEnv,
				allowedScopes: commaList.optional(),
				allowedAudiences: commaList.optional(),
				allowedHosts: commaList.optional(),
				deniedHosts: commaList.optional(),
				maxBytes: wholeNumberInRangeFromEnv(1).optional(),
				timeoutMs: wholeNumberInRangeFromEnv(1).optional(),
				cacheMaxAgeMs: wholeNumberInRangeFromEnv(0).optional(),
				maxCacheEntries: wholeNumberInRangeFromEnv(1).optional(),
				staleIfErrorMs: wholeNumberInRangeFromEnv(0).optional(),
				negativeCacheMs: wholeNumberInRangeFromEnv(0).optional(),
				maxConcurrentFetches: wholeNumberInRangeFromEnv(1).optional(),
			})
			.strict()
			.optional(),
		// The paths other modules' sections, and core's token-binding settings,
		// moved from.
		grants: movedAway,
		code: movedAway,
		deviceAuthorization: movedAway,
		tokenExchange: movedAway,
		mtls: movedAway,
		dpop: movedAway,
		tokenBinding: movedAway,
		// What revocation promises:
		//   accessToken — what `POST /oauth/revoke` does with an access token:
		//     "denylist" writes its `jti` to the `accessTokenDenylist` slot, which
		//     boot then requires; "unsupported" answers `unsupported_token_type`.
		//   subject — the declared absence of both subject-level revocation slots
		//     (`subjectRevocation`, `subjectSessionIndex`), read only when one is
		//     unfilled.
		revocation: z
			.object({
				accessToken: z.enum(["denylist", "unsupported"]),
				subject: z.enum(["watermark", "unsupported"]).optional(),
			})
			.strict()
			.optional(),
	})
	.strict();

/** `oauth {}` as this module's schema parsed it: what `deps.section` holds. */
export type OAuthSection = z.output<typeof oauthSectionSchema>;
