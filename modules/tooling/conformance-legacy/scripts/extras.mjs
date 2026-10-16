// The packages the standalone build does not load, or loads in a form a scene cannot reach, by the
// name a part asks for each with, and the legacy package directories each needs. The composed entry
// loads them; prepare-legacy builds them.
export const extras = {
	mtls: ["mtls"],
	github: ["federation-github"],
	google: ["federation-google"],
	apple: ["federation-apple"],
	webauthn: ["webauthn"],
	// The WebAuthn second factor, named with `webauthn`, which gives it the relying party.
	"webauthn-mfa": ["webauthn"],
	"token-exchange": ["oauth-token-exchange"],
	"device-grant": ["device-grant"],
	dpop: ["dpop"],
};
