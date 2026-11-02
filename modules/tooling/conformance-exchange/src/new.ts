import { type NewPart, onNew } from "@mod/conformance";
import { type AppleIdTokensPart, type ExchangePart, exchangeArea } from "./area.ts";

/** Apple's issuer and the host of its key set, as exchange-id-tokens fixes them. */
const apple = { issuer: "https://appleid.apple.com", host: "appleid.apple.com" };

/**
 * Apple's id_tokens taken by both grants: exchange-id-tokens for the clients named, the JWT bearer
 * grant delegating Apple's issuer to it, and outbound reaching Apple's key set.
 */
const appleSections = (at: AppleIdTokensPart) => ({
	"exchange-id-tokens": {
		apple: {
			clients: Object.fromEntries(
				Object.entries(at.clients).map(([id, audiences]) => [id, { audiences }]),
			),
		},
	},
	"jwt-bearer": { "delegated-issuers": [apple.issuer] },
	outbound: { allow: [apple.host], ...(at.proxy ? { proxy: at.proxy } : {}) },
});

const setUp = (part: ExchangePart): NewPart => ({
	modules: [
		"@mod/token-exchange",
		...(part.appleIdTokens
			? [
					"@mod/outbound",
					"@mod/external-jwt",
					"@mod/exchange-id-tokens",
					"@mod/jwt-bearer",
					"@mod/jwt-bearer-id-tokens",
				]
			: []),
	],
	store: "volatile",
	config: {
		"token-exchange": {
			...(part.maxActorDepth ? { "max-actor-depth": part.maxActorDepth } : {}),
			...(part.maxLifetimeSeconds ? { "max-lifetime": `${part.maxLifetimeSeconds}s` } : {}),
		},
		...(part.appleIdTokens ? appleSections(part.appleIdTokens) : {}),
	},
});

const unvouched =
	"a grant without a session on an app with a user ledger and verified-email: no source can vouch for the subject's email";

onNew(exchangeArea, setUp, (part, _, modules) =>
	part.sessionless && ["@mod/users-http", "@mod/verified-email"].every((m) => modules.includes(m))
		? { leaveOut: unvouched }
		: setUp(part),
);
