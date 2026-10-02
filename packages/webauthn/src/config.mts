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
 * A bootstrap module parses the `webauthn` section with `webauthnConfigSchema` and supplies it
 * through the `webauthnConfig` ComponentMap slot; core does not merge it into AppConfigSchema.
 * The schema has no `.default()`: every default lives in `packages/webauthn/config/reference.conf`
 * (packages/core/docs/adr/2026-04-30-config-schema-strict-defaults-from-hocon.md).
 *
 * A HOCON `${?VAR}` substitution is always a string, so every leaf an environment variable can
 * reach is read in that form: numbers through core's `wholeNumberInRangeFromEnv`, origin lists
 * through core's `normalizeAllowedOrigins`.
 */
import {
	// biome-ignore lint/correctness/noUnusedImports: ComponentMap is used in the `declare module` augmentation below; biome does not track cross-module-declaration references.
	type ComponentMap as _ComponentMap,
	checkSerializedOrigin,
	describeSerializedOriginRejection,
	MAX_DURATION_SECONDS,
	normalizeAllowedOrigins,
	wholeNumberInRangeFromEnv,
} from "@o3co/auth-provider-core";
import { z } from "zod";

/**
 * Reads `origin` / `topOrigin` as a config-file list or as the comma-separated string
 * `${?WEBAUTHN_ORIGIN}` / `${?WEBAUTHN_TOP_ORIGIN}` delivers.
 *
 * A string goes through core's `normalizeAllowedOrigins`, as a CORS origin list's does: split on
 * commas, trimmed, empties dropped; a refusal's index counts entries after that. In a list, string
 * entries are trimmed and any other entry keeps its index for the schema to refuse (not dropped,
 * which would shorten the operator's list). Any other shape passes through, refused as the wrong
 * type rather than read as an empty list.
 */
const readOriginList = (raw: unknown): unknown => {
	if (typeof raw === "string") return normalizeAllowedOrigins(raw);
	if (Array.isArray(raw))
		return raw.map((entry) => (typeof entry === "string" ? entry.trim() : entry));
	return raw;
};

/**
 * {@link readOriginList} for the optional `topOrigin`, where an exported-but-
 * empty variable reads as unset — not framed — as an empty CORS origin list
 * reads as CORS off. An explicit empty list is still
 * refused.
 */
const readTopOriginList = (raw: unknown): unknown => {
	const read = readOriginList(raw);
	return typeof raw === "string" && Array.isArray(read) && read.length === 0 ? undefined : read;
};

/**
 * An Android app origin, `android:apk-key-hash:<base64url>`, which Credential Manager sends in
 * place of an https origin. The body is the unpadded base64url SHA-256 of the app's signing
 * certificate; the signing key, held only by the publisher, is the guarantee. SimpleWebAuthn
 * matches it against clientDataJSON by exact string.
 *
 * Checked on the raw string: it has no host to parse, and `new URL()` would accept
 * `android:apk-key-hash:../evil`. The shape is the whole check:
 * - the lowercase prefix, the spelling clients send (another case would never match);
 * - 43 URL-safe characters: 256 bits are 42 full characters plus one holding 4 bits, its low
 *   2 bits zero (hence the last class). This refuses padding, standard-base64 `+` / `/`,
 *   truncation, and keytool's hex fingerprint (64 characters, all valid base64url);
 * - nothing after the body (no path, query or fragment).
 */
const ANDROID_APK_KEY_HASH_ORIGIN = /^android:apk-key-hash:[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** The refusal for an entry that starts like the Android form and misses it. */
const ANDROID_ORIGIN_SHAPE =
	"an Android app origin must be android:apk-key-hash: followed by the unpadded base64url " +
	"SHA-256 of the signing certificate (43 characters), not the hex fingerprint — the lowercase " +
	"prefix, and nothing after it";

/** An IPv4 host as a serialized origin spells it; an IPv6 one is bracketed. */
const IPV4_HOST = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/**
 * Why a web entry of `origin` or `topOrigin` cannot be used, or `null`.
 *
 * First core's `checkSerializedOrigin`, the rule a CORS origin list follows: SimpleWebAuthn
 * compares each entry by exact string with the origin the browser serialized into clientDataJSON,
 * so an entry that is not that serialization (trailing slash, path, userinfo, uppercase host,
 * default port, wildcard) matches no ceremony. `https:` is required except on a loopback host:
 * passkeys need a secure context (W3C WebAuthn §5.1.3).
 *
 * Then the host must be a domain: WebAuthn §5.1.3 and §5.1.4.1 refuse a ceremony whose effective
 * domain is not a valid domain, so no browser can use an IP literal, loopback included.
 * `localhost` works.
 */
function webOriginProblem(entry: string): string | null {
	const rejection = checkSerializedOrigin(entry);
	if (rejection !== null) return describeSerializedOriginRejection(rejection);
	const { hostname } = new URL(entry);
	if (hostname.startsWith("[") || IPV4_HOST.test(hostname)) {
		return (
			"WebAuthn needs a domain, not an IP address — a browser refuses a ceremony on an " +
			"IP-literal origin (W3C WebAuthn §5.1.3); for local development use localhost"
		);
	}
	return null;
}

/**
 * A `topOrigin` entry: a web origin ({@link webOriginProblem}). An Android
 * app origin is refused by name: it is what Credential Manager sends *as* the
 * origin, and no browsing context frames it.
 */
const webOriginEntry = z.string().superRefine((entry, ctx) => {
	const problem = /^android:/i.test(entry)
		? "an Android app origin is never a top origin: Credential Manager sends it as the " +
			"ceremony's own origin, and no browsing context frames it"
		: webOriginProblem(entry);
	if (problem !== null) ctx.addIssue({ code: "custom", message: problem });
});

/**
 * An `origin` entry: a web origin ({@link webOriginProblem}), or an Android
 * app origin — see {@link ANDROID_APK_KEY_HASH_ORIGIN}. An entry that starts
 * like the Android form and misses its shape is told what the shape is,
 * rather than refused as a web origin with no tuple origin.
 */
const originEntry = z.string().superRefine((entry, ctx) => {
	if (ANDROID_APK_KEY_HASH_ORIGIN.test(entry)) return;
	const problem = /^android:/i.test(entry) ? ANDROID_ORIGIN_SHAPE : webOriginProblem(entry);
	if (problem !== null) ctx.addIssue({ code: "custom", message: problem });
});

export const webauthnConfigSchema = z.object({
	/** Relying Party ID — the effective domain, e.g. "example.com". */
	rpId: z.string().min(1),
	/** Human-readable Relying Party name shown to the user during ceremony. */
	rpName: z.string().min(1),
	/**
	 * Allowed origins for registration and authentication ceremonies; at least one. Several
	 * entries let sub-domains or apps share one `rpId`.
	 *
	 * A web origin is a bare serialized origin, with a port only when it is not the default:
	 * `https://example.com`, `https://app.example.com:8443`, `http://localhost:3000`. No trailing
	 * slash, path, wildcard or userinfo; `https:` except on a loopback host; a domain, not an IP
	 * address ({@link webOriginProblem}).
	 *
	 * An Android app origin, `android:apk-key-hash:<base64url>`, is also accepted, so the site and
	 * the app can share one `rpId` ({@link ANDROID_APK_KEY_HASH_ORIGIN}).
	 *
	 * From the environment, `WEBAUTHN_ORIGIN` is a comma-separated list.
	 */
	origin: z.preprocess(readOriginList, z.array(originEntry).min(1)),
	/**
	 * Origins this RP may be framed by: the parent pages' origins (not this RP's) that a browser
	 * reports as `topOrigin` for a cross-origin (iframe) ceremony. Optional; absent, a
	 * registration or authentication response reporting a cross-origin `topOrigin` is refused, the
	 * right answer for a deployment never meant to be embedded. Enforced only where the browser
	 * reports one (Safari does not).
	 *
	 * Same rules as `origin`'s web entries; the Android app form is refused, since nothing frames
	 * it. From the environment, `WEBAUTHN_TOP_ORIGIN` is a comma-separated list, and an empty
	 * value is unset.
	 */
	topOrigin: z.preprocess(readTopOriginList, z.array(webOriginEntry).min(1).optional()).optional(),
	/**
	 * Challenge time-to-live in milliseconds. Default 120000 (120 s), sized for slow mobile
	 * networks.
	 */
	challengeTtlMs: wholeNumberInRangeFromEnv(1),
	/**
	 * AttestationConveyancePreference (W3C WebAuthn §5.4.7). Default "none": no attestation chain
	 * is verified. Set "direct" only with a curated trust-anchor set.
	 */
	attestationPreference: z.enum(["none", "indirect", "direct", "enterprise"]),
	/** UserVerificationRequirement (W3C WebAuthn §5.8.6). Default "preferred". */
	userVerification: z.enum(["required", "preferred", "discouraged"]),
	/** Rate limits for the module's own endpoints, one entry per endpoint. */
	rateLimit: z.object({
		/**
		 * `POST /oauth/webauthn/authentication/options`, which is unauthenticated and writes a
		 * challenge per request: `limit` requests per `windowSeconds` per source IP. Defaults 30 per
		 * 60 s. Feeds core as a `RateLimitSpec`; like core's `rateLimitSpecSchema`, the window is at
		 * most one year, since no limiter can apply a window past the Date range.
		 */
		authenticationOptions: z.object({
			limit: wholeNumberInRangeFromEnv(1),
			windowSeconds: wholeNumberInRangeFromEnv(1, MAX_DURATION_SECONDS),
		}),
	}),
});

export type WebAuthnConfig = z.infer<typeof webauthnConfigSchema>;

// Declares the typed `webauthnConfig` ComponentMap slot. Augments the package name, not a relative
// path, as every cross-package ComponentMap augmentation does.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly webauthnConfig?: WebAuthnConfig;
	}
}
