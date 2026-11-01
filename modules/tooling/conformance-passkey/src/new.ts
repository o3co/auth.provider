import { type NewPart, onNew } from "@mod/conformance";
import { type PasskeyPart, passkeyArea } from "./area.ts";
import { witnessLedger } from "./ledger.ts";

/** passkey-witness-http pointed at the scene's ledger, which outbound reaches at loopback over plain http. */
const witnessAt = (section: Readonly<Record<string, unknown>>) => {
	const at = new URL(String(section["read-url"]));
	return {
		"passkey-witness-http": section,
		outbound: { allow: [at.hostname], "plain-loopback": [at.host] },
	};
};

const setUp = (part: PasskeyPart): NewPart => ({
	modules: [
		"@mod/webauthn",
		"@mod/passkeys",
		"@mod/passkey-registration",
		...(part.login ? ["@mod/webauthn-login"] : []),
		...(part.secondFactor ? ["@mod/mfa-webauthn"] : []),
		...(part.session ? ["@mod/login-passkey"] : []),
		...(part.session?.witness ? ["@mod/passkey-witness-http", "@mod/passkey-witnessing"] : []),
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
		...(part.session
			? {
					"login-passkey": {
						...(part.session.attempts ? { attempts: part.session.attempts } : {}),
						...(part.session.windowSeconds ? { window: `${part.session.windowSeconds}s` } : {}),
						...(part.session.countsAsMfa === undefined
							? {}
							: { "counts-as-mfa": part.session.countsAsMfa }),
						...(part.session.password ? { password: part.session.password } : {}),
					},
					...(part.session.witness ? witnessAt(part.session.witness) : {}),
				}
			: {}),
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

const noSessionLogin = "a passkey login into a browser session, which the app does not compose";
const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(passkeyArea, setUp, (part, _, modules) => {
	if (part.login && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))) {
		return { leaveOut: unvouched };
	}
	if (part.session && !modules.includes("@mod/login-passkey")) return { leaveOut: noSessionLogin };
	// An app keeping passkeys' witness at a ledger asks it at each registration: a fake ledger keeps it.
	if (!modules.includes("@mod/passkey-witness-http")) return setUp(part);
	const set = setUp(part);
	return { ...set, whole: [...(set.whole ?? []), "passkey-witness-http"], party: witnessLedger };
});
