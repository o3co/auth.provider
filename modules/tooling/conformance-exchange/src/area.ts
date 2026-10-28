import { type AreaScene, area } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import type { UserScene } from "@mod/conformance-identity";
import type { KeysPart } from "@mod/conformance-keys";
import type { ClientScene } from "@mod/conformance-oauth";

/** Token Exchange (RFC 8693), for the clients allowed it. */
export interface ExchangePart {
	/** How many actors an issued token's chain may hold. */
	readonly maxActorDepth?: number;
	/** The longest lifetime, in seconds, an exchanged token gets, whatever lifetime the request asks. */
	readonly maxLifetimeSeconds?: number;
	/** The scene exchanges subject tokens that carry no session, such as a refresh family's. */
	readonly sessionless?: true;
}

export const exchangeArea = area<ExchangePart>("exchange");

/** An exchange scene, in the shape the scenes write it. */
export interface ExchangeScene extends ExchangePart {
	readonly issuer: string;
	readonly keys?: KeysPart;
	readonly clients: readonly ClientScene[];
	readonly users: readonly UserScene[];
	/** Sender-constrained tokens by DPoP (RFC 9449). */
	readonly dpop?: boolean;
	/** No token for a user whose account does not state the email verified, as the OAuth area sets it up. */
	readonly verifiedEmail?: true;
	/** The rule for the audience a request asks (RFC 8707), which token exchange never takes. */
	readonly resourceIndicators?: boolean;
	/** Modules the scene is about the absence of, as the code area takes them. */
	readonly without?: readonly string[];
}

/** The code flow with refresh, introspection and revocation give the tokens to exchange and to check. */
export function exchangeScene(scene: ExchangeScene): AreaScene {
	const built = codeScene({
		issuer: scene.issuer,
		...(scene.keys ? { keys: scene.keys } : {}),
		clients: scene.clients,
		users: scene.users,
		refresh: {},
		introspection: true,
		revocation: true,
		...(scene.dpop ? { dpop: true } : {}),
		...(scene.verifiedEmail ? { verifiedEmail: true } : {}),
		...(scene.resourceIndicators ? { resourceIndicators: true } : {}),
		...(scene.without ? { without: scene.without } : {}),
	});
	const [name, part] = exchangeArea.part({
		...(scene.maxActorDepth ? { maxActorDepth: scene.maxActorDepth } : {}),
		...(scene.maxLifetimeSeconds ? { maxLifetimeSeconds: scene.maxLifetimeSeconds } : {}),
		...(scene.sessionless ? { sessionless: true } : {}),
	});
	return { ...built, parts: { ...built.parts, [name]: part } };
}
