import { type NewPart, onNew } from "@mod/conformance";
import { type PasskeyPart, passkeyArea } from "./area.ts";

const setUp = (part: PasskeyPart): NewPart => ({
	modules: [
		"@mod/webauthn",
		"@mod/passkey-registration",
		...(part.login ? ["@mod/webauthn-login"] : []),
		...(part.secondFactor ? ["@mod/mfa-webauthn"] : []),
	],
	store: "volatile",
	config: {
		webauthn: {
			"rp-id": part.rpId,
			"rp-name": "Conformance",
			origins: [...part.origins],
			...(part.topOrigins ? { "top-origins": [...part.topOrigins] } : {}),
			...(part.userVerification ? { "user-verification": part.userVerification } : {}),
			...(part.challengeSeconds ? { "challenge-lifetime": `${part.challengeSeconds}s` } : {}),
			...(part.maxCredentials ? { "max-credentials": part.maxCredentials } : {}),
		},
		...(part.login
			? {
					"webauthn-login": {
						requests: part.login.requests,
						"window-seconds": part.login.windowSeconds,
					},
				}
			: {}),
	},
});

const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(passkeyArea, setUp, (part, _, modules) =>
	part.login && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))
		? { leaveOut: unvouched }
		: setUp(part),
);
