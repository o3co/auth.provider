import { type NewPart, onNew } from "@mod/conformance";
import { type PasskeyPart, passkeyArea } from "./area.ts";
import { witnessLedger } from "./ledger.ts";

const setUp = (part: PasskeyPart): NewPart => ({
	modules: [
		"@mod/webauthn",
		"@mod/passkeys",
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
			...(part.challengeSeconds ? { "challenge-lifetime": `${part.challengeSeconds}s` } : {}),
		},
		passkeys: {
			...(part.userVerification ? { "user-verification": part.userVerification } : {}),
			...(part.maxCredentials ? { "max-credentials": part.maxCredentials } : {}),
		},
		...(part.login
			? {
					"webauthn-login": {
						requests: part.login.requests,
						window: `${part.login.windowSeconds}s`,
					},
				}
			: {}),
	},
});

const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(passkeyArea, setUp, (part, _, modules) => {
	if (part.login && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))) {
		return { leaveOut: unvouched };
	}
	// An app keeping passkeys' witness at a ledger asks it at each registration: a fake ledger keeps it.
	if (!modules.includes("@mod/passkey-witness-http")) return setUp(part);
	const set = setUp(part);
	return { ...set, whole: [...(set.whole ?? []), "passkey-witness-http"], party: witnessLedger };
});
