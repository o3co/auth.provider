import { onLegacy } from "@mod/conformance-legacy";
import { oauthArea } from "@mod/conformance-oauth";
import { type PasskeyPart, passkeyArea } from "./area.ts";

/** The options route's budget, under the tag the build's in-memory limiter keys it by. */
const loginSettings = (login: PasskeyPart["login"]) =>
	login
		? `core-rate-limiter-memory.limits.webauthn-authentication-options { limit = ${login.requests}, windowSeconds = ${login.windowSeconds} }\n`
		: "";

onLegacy(passkeyArea, {
	// The standalone build loads neither WebAuthn nor DPoP; the composed entry adds them, with stores in memory.
	map: (part, scene) => ({
		env: {
			WEBAUTHN_RP_ID: part.rpId,
			WEBAUTHN_RP_NAME: "Conformance",
			WEBAUTHN_ORIGIN: part.origins.join(","),
			...(part.topOrigins ? { WEBAUTHN_TOP_ORIGIN: part.topOrigins.join(",") } : {}),
			...(part.userVerification ? { WEBAUTHN_USER_VERIFICATION: part.userVerification } : {}),
			...(part.challengeSeconds
				? { WEBAUTHN_CHALLENGE_TTL_MS: String(part.challengeSeconds * 1000) }
				: {}),
			...(part.secondFactor ? { WEBAUTHN_MFA_FACTOR_ENABLED: "true" } : {}),
		},
		settings:
			loginSettings(part.login) +
			(part.login && oauthArea.in(scene)?.dpop ? "dpop { enabled = true }\n" : ""),
		extra: [
			"webauthn",
			...(part.secondFactor ? ["webauthn-mfa"] : []),
			...(part.login && oauthArea.in(scene)?.dpop ? ["dpop"] : []),
		],
	}),
	cannot: [
		// The composed entry keeps passkeys and challenges in memory, which no store failure reaches.
		"store-fault:passkeys",
		// The legacy build keeps no limit of passkeys per user.
		"passkey-credential-limit",
	],
	differs: [
		// A framed ceremony whose browser reports no top origin is accepted with no frame listed.
		"passkey-framed-without-top-origin",
		// A response without user verification, when it is required, is answered as unknown.
		"passkey-user-verification-unknown",
		// Ours redeems a challenge only for the client that asked for its options.
		"passkey-challenge-bound-to-client",
		// With a verified email required, passkey login does not start over a users file.
		"email-gate-without-subject-lookup",
		// The legacy build's passkeys prove `hwk` (or `swk` as a second factor), ours `pop`: no attestation tells how a key is kept.
		"passkey-amr-pop",
	],
});
