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
 * WebAuthn deployer configuration schema.
 *
 * Parsed by `webauthnConfigSchema` and supplied to `webauthnModule` via the
 * bootstrap module's `provides: { webauthnConfig }` ComponentMap slot
 * (spec §2.4.1 — this package exports the schema; auth-provider-core does
 * NOT auto-intersect it into AppConfigSchema).
 *
 * Schema design principle: pure type contract (ADR 2026-04-30).
 * No `.default()` calls — all runtime defaults live exclusively in
 * `packages/webauthn/config/reference.conf` (HOCON). The ADR rule is
 * project-wide (see `tokenExchangeConfigSchema` in oauth-token-exchange
 * for the nearest analogous module-local schema). Schema parse rejects
 * bare inputs without all required fields; tests supply every field
 * explicitly rather than relying on hidden schema-side defaults.
 *
 * S11 baseline (dogfood-friendly):
 *   attestationPreference = "none"   — no attestation chain verification required;
 *                                       deployments needing device attestation
 *                                       override to "direct" + supply trust anchors.
 *   challengeTtlMs = 120_000         — 120 s; chosen as the mobile-network safe
 *                                       baseline (per spec §2.4.1 / FCoT CA4).
 *   userVerification = "preferred"   — balance between broad platform coverage
 *                                       and security posture.
 *
 * #281 baselines (authentication/options hardening):
 *   allowCredentialsForKnownUser = false     — the endpoint never answers
 *                                       "does this account exist?".
 *   rateLimit.authenticationOptions = 30/60s — an unauthenticated endpoint
 *                                       that writes a challenge per request
 *                                       is throttled by default, not only
 *                                       when an operator remembers to.
 *
 * Every leaf an environment variable can reach through reference.conf is
 * read here in the string form it arrives in, the way core's application
 * schema reads its own (#288): a HOCON `${?VAR}` substitution is always a
 * string. Numbers go through `z.coerce.number()`; booleans through core's
 * `coerceBooleanFromEnv`, so `WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER`
 * takes the same four spellings as every other switch and refuses the rest;
 * the two origin lists through core's `normalizeAllowedOrigins`, so
 * `WEBAUTHN_ORIGIN` / `WEBAUTHN_TOP_ORIGIN` are comma-separated like
 * `CORS_ALLOWED_ORIGINS`.
 */
import {
	// biome-ignore lint/correctness/noUnusedImports: ComponentMap is used in the `declare module` augmentation below; biome does not track cross-module-declaration references.
	type ComponentMap as _ComponentMap,
	checkSerializedOrigin,
	coerceBooleanFromEnv,
	describeSerializedOriginRejection,
	normalizeAllowedOrigins,
} from "@o3co/auth-provider-core";
import { z } from "zod";

/**
 * `origin` / `topOrigin` in both of their spellings: the list a config file
 * carries, or the one string `${?WEBAUTHN_ORIGIN}` / `${?WEBAUTHN_TOP_ORIGIN}`
 * delivers, comma-separated — an environment variable cannot carry a list any
 * other way.
 *
 * The string is read by core's `normalizeAllowedOrigins`, the reader
 * `CORS_ALLOWED_ORIGINS` goes through, so every origin list an operator sets
 * from the environment is spelled alike: split on commas, each entry trimmed,
 * the empty ones dropped. The split yields only pieces of what the operator
 * wrote, and each piece meets the rules below as a list entry would, so the
 * string cannot admit an origin the list would refuse. An index in a refusal
 * counts entries after the split, empty ones already dropped.
 *
 * A list keeps every entry where it is: a string entry is trimmed, and any
 * other entry is left for the schema to refuse at its index — not dropped,
 * which is what core's reader does for CORS, and which would shorten the
 * list the operator wrote. Any other shape is handed on as it is, so the
 * schema refuses it as the wrong type rather than as an empty list.
 */
const readOriginList = (raw: unknown): unknown => {
	if (typeof raw === "string") return normalizeAllowedOrigins(raw);
	if (Array.isArray(raw))
		return raw.map((entry) => (typeof entry === "string" ? entry.trim() : entry));
	return raw;
};

/**
 * {@link readOriginList} for the optional `topOrigin`, where an exported-but-
 * empty variable reads as unset — not framed — as an empty
 * `CORS_ALLOWED_ORIGINS` reads as CORS off. An explicit empty list is still
 * refused.
 */
const readTopOriginList = (raw: unknown): unknown => {
	const read = readOriginList(raw);
	return typeof raw === "string" && Array.isArray(read) && read.length === 0 ? undefined : read;
};

/**
 * Android's Credential Manager presents the calling app as
 * `android:apk-key-hash:<base64url>` — the base64url SHA-256 of the signing
 * certificate — where a browser presents an https origin. It is not a URL with
 * a host, so the serialized-origin rule below (scheme + loopback carve-out)
 * has nothing to say about it; the guarantee is the signing key itself, which
 * only the app publisher holds.
 *
 * `@simplewebauthn/server` accepts this form and matches it against
 * clientDataJSON by exact string, like every other expected origin. Until #497
 * the schema refused it, so the "one RP shared by the web origin and the
 * Android app" deployment this package's README describes could not be
 * expressed in configuration at all.
 *
 * Validated on the RAW string, not on a parsed `URL`: the value is an opaque
 * URI whose body is not a host, so there is nothing for the parse to check —
 * and `new URL()` would happily accept `android:apk-key-hash:../evil` too.
 * The shape is therefore the whole check:
 *
 * - the literal lowercase prefix, because that is the spelling the client
 *   sends and the comparison is exact — `ANDROID:APK-KEY-HASH:` would parse
 *   and then never match a ceremony, the same dead-entry failure the
 *   serialized-origin rule below exists to prevent for a web origin;
 * - a non-empty base64url body (`A-Za-z0-9-_` with optional `=` padding) and
 *   nothing after it, so a path, query or fragment smuggled onto the end is
 *   refused rather than registered.
 *
 * Standard-base64 `+` and `/` are deliberately out: the alphabet Credential
 * Manager emits is the URL-safe one, so those characters can only be a
 * transcription error.
 */
const ANDROID_APK_KEY_HASH_ORIGIN = /^android:apk-key-hash:[A-Za-z0-9_-]+={0,2}$/;

/**
 * One web entry of `origin` or `topOrigin`: a bare serialized origin, held to
 * core's `checkSerializedOrigin` — the rule `cors.allowedOrigins` is held to,
 * for the same reason. SimpleWebAuthn compares each entry with the origin the
 * browser serialized into clientDataJSON by exact string, so an entry that
 * parses but is not that serialization — a trailing slash, a path, query or
 * fragment, userinfo, an uppercase host, an explicit default port, a
 * wildcard — matches no ceremony. `https:` is required except for a host
 * core's loopback vocabulary names (`localhost`, `127.0.0.0/8`, `[::1]`):
 * passkeys need a secure context (W3C WebAuthn §5.1.3), and a browser treats
 * those hosts as one. The refusal is core's wording, and a not-serialized
 * entry is told the origin it should have been.
 */
const webOriginEntry = z.string().superRefine((entry, ctx) => {
	const rejection = checkSerializedOrigin(entry);
	if (rejection !== null) {
		ctx.addIssue({ code: "custom", message: describeSerializedOriginRejection(rejection) });
	}
});

/**
 * An `origin` entry: a web origin as above, or an Android app origin — see
 * {@link ANDROID_APK_KEY_HASH_ORIGIN}. An entry that starts like the Android
 * form and misses its shape is told so, rather than refused as a web origin
 * with no tuple origin.
 */
const originEntry = z.string().superRefine((entry, ctx) => {
	if (ANDROID_APK_KEY_HASH_ORIGIN.test(entry)) return;
	if (/^android:/i.test(entry)) {
		ctx.addIssue({
			code: "custom",
			message:
				"an Android app origin must be android:apk-key-hash:<base64url> — the lowercase prefix, " +
				"a URL-safe base64 body, and nothing after it",
		});
		return;
	}
	const rejection = checkSerializedOrigin(entry);
	if (rejection !== null) {
		ctx.addIssue({ code: "custom", message: describeSerializedOriginRejection(rejection) });
	}
});

export const webauthnConfigSchema = z.object({
	/** Relying Party ID — the effective domain, e.g. "example.com". */
	rpId: z.string().min(1),
	/** Human-readable Relying Party name shown to the user during ceremony. */
	rpName: z.string().min(1),
	/**
	 * Allowed HTTPS origin(s) for registration / authentication ceremonies.
	 * At least one entry required. Multiple entries support sub-domain or
	 * multi-app deployments sharing a single RP ID.
	 *
	 * Each web origin is a bare serialized origin — scheme + host + a port only
	 * when it is not the default: `https://example.com`,
	 * `https://app.example.com:8443`, `http://localhost:3000`. No trailing
	 * slash, path, wildcard or userinfo, and `https:` except on a loopback
	 * host; see {@link webOriginEntry} for why each is refused at boot.
	 *
	 * An **Android app** origin is the one non-URL entry this list accepts:
	 * `android:apk-key-hash:<base64url>`, what Credential Manager sends in place
	 * of an https origin (#497). List it alongside the web origin to share one
	 * `rpId` between the site and the app — see ANDROID_APK_KEY_HASH_ORIGIN
	 * above for the shape and why it is checked on the raw string.
	 *
	 * From the environment, `WEBAUTHN_ORIGIN` is a comma-separated list — see
	 * {@link readOriginList}.
	 *
	 * Cross-refs: Wave 1 post-merge audit M-1; #497.
	 */
	origin: z.preprocess(readOriginList, z.array(originEntry).min(1)),
	/**
	 * Origins this RP may be **framed by** — the `topOrigin` a browser reports
	 * for a cross-origin (iframe) ceremony (#554 audit).
	 *
	 * Optional, and absent is the safe default: SimpleWebAuthn 14 refuses an
	 * authentication response whose `topOrigin` the browser reported unless it
	 * is given an expected value, which is the right answer for a deployment
	 * that never meant to be embedded. Set it to the embedding origins a
	 * deployment does intend — the parent page's origin, not this RP's — and
	 * cross-origin passkey authentication from those frames is accepted.
	 *
	 * The same rule as `origin`'s web entries ({@link webOriginEntry}). Not the
	 * Android app form: `android:apk-key-hash:` is what Credential Manager
	 * sends *as* the origin, and there is no browsing context above it to be a
	 * top origin.
	 *
	 * Safari does not send `topOrigin` as of the 14.0.1 vendoring, so the
	 * library only enforces this where the browser reports one.
	 *
	 * From the environment, `WEBAUTHN_TOP_ORIGIN` is a comma-separated list, and
	 * an empty one is unset — see {@link readTopOriginList}.
	 */
	topOrigin: z.preprocess(readTopOriginList, z.array(webOriginEntry).min(1).optional()).optional(),
	/**
	 * Challenge time-to-live in milliseconds.
	 * Reference default (S11): 120_000 ms — mobile-network safe baseline.
	 * Supplied via reference.conf per ADR 2026-04-30; `z.coerce` because
	 * `${?WEBAUTHN_CHALLENGE_TTL_MS}` arrives as a string.
	 */
	challengeTtlMs: z.coerce.number().int().positive(),
	/**
	 * WebAuthn AttestationConveyancePreference (W3C WebAuthn §5.4.7).
	 * Reference default (S11): "none" — dogfood-friendly; no attestation
	 * chain verification required. Supplied via reference.conf.
	 */
	attestationPreference: z.enum(["none", "indirect", "direct", "enterprise"]),
	/**
	 * WebAuthn UserVerificationRequirement (W3C WebAuthn §5.8.6).
	 * Reference default (S11): "preferred". Supplied via reference.conf.
	 */
	userVerification: z.enum(["required", "preferred", "discouraged"]),
	/**
	 * Opt back in to deriving `allowCredentials` on
	 * `POST /oauth/webauthn/authentication/options` from the `userId` the
	 * request body supplies. Reference default: `false` (#281).
	 *
	 * With `false` the endpoint always returns the discoverable-credential
	 * shape: no `allowCredentials` member, no credential-store lookup, and a
	 * response that is identical for a registered account, an unregistered
	 * one, and a request that named no account at all. That uniformity is the
	 * whole point — the previous behaviour answered an unauthenticated
	 * "does this account exist, and how many passkeys does it have?" query
	 * for anyone who asked.
	 *
	 * Set `true` ONLY for a deployment whose authenticators cannot do
	 * discoverable credentials (non-resident keys — typically older
	 * security-key fleets), where the client must be told which credential
	 * ids to offer. It re-enables the enumeration oracle for that deployment,
	 * knowingly: pair it with a hard rate limit
	 * (`rateLimit.authenticationOptions`) and prefer gating the endpoint
	 * behind an authenticated identifier-first step where you can.
	 *
	 * `${?WEBAUTHN_ALLOW_CREDENTIALS_FOR_KNOWN_USER}` arrives as a string:
	 * "true" / "1" turn it on, "false" / "0" (or an empty value) leave it off —
	 * case and surrounding spaces ignored — and any other value fails the
	 * parse.
	 */
	allowCredentialsForKnownUser: coerceBooleanFromEnv,
	/**
	 * Rate limits for the module's own endpoints.
	 *
	 * Nested (rather than a flat `authenticationOptionsRateLimit`) so the
	 * registration endpoints can gain their own entries without a second
	 * naming convention.
	 */
	rateLimit: z.object({
		/**
		 * `POST /oauth/webauthn/authentication/options` — unauthenticated by
		 * design, and it writes a challenge per request. `limit` requests per
		 * `windowSeconds` per source IP; reference defaults 30 / 60 s.
		 *
		 * `z.coerce` because HOCON env substitution
		 * (`${?WEBAUTHN_AUTHENTICATION_OPTIONS_RATE_LIMIT}`) yields strings —
		 * matching `rateLimitSpecSchema` in core's application schema, which
		 * this shape feeds as a `RateLimitSpec`.
		 */
		authenticationOptions: z.object({
			limit: z.coerce.number().int().positive(),
			windowSeconds: z.coerce.number().int().positive(),
		}),
	}),
});

export type WebAuthnConfig = z.infer<typeof webauthnConfigSchema>;

// ComponentMap slot declaration-merge: exposes webauthnConfig as a typed DI
// slot. Consumers supply this via a small bootstrap module that reads from
// app config (per A5 §10.2 const-Module pattern). Uses the package-name path
// (not a relative import) consistent with the T21-established pattern for
// cross-package ComponentMap augmentation.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly webauthnConfig?: WebAuthnConfig;
	}
}
