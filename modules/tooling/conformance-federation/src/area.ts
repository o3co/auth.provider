import { type AreaScene, area, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import { identityArea, type RevocationScene, type UserScene } from "@mod/conformance-identity";
import { type KeysPart, keysArea } from "@mod/conformance-keys";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";

/** An upstream OpenID Connect IdP the deployment logs browsers in through. */
export interface IdpScene {
	/** The IdP's name: its path segment, and the first half of a user's upstream link. */
	readonly name: string;
	/** OpenID Connect (the default), or GitHub's, Google's or Apple's own at `issuer`, standing for their hosts. */
	readonly type?: "oidc" | "github" | "google" | "apple";
	readonly issuer: string;
	readonly clientId: string;
	/** Required by every type but Apple, which takes it or `signing`. */
	readonly clientSecret?: string;
	/** Apple only: what signs the client's secret (all three, unless a scene means to leave some out). */
	readonly signing?: {
		readonly teamId?: string;
		readonly keyId?: string;
		/** PKCS8 PEM. */
		readonly privateKey?: string;
	};
}

/** What a federation grant may be for: one IdP, the scopes the user may be asked for. */
export interface ConnectionScene {
	readonly name: string;
	readonly idp: string;
	readonly scopes: readonly string[];
	/** The longest an upstream access token may live to be kept. */
	readonly maxAccessTokenSeconds: number;
	/** A client may ask for fewer of the scopes. */
	readonly scopeSubsets?: boolean;
}

/** Federation grants: the consent page and the connections offered. */
export interface GrantsPart {
	readonly page: string;
	readonly connections: readonly ConnectionScene[];
	/** How many intents one client may lodge in a window, whatever user it names. */
	readonly lodges?: { readonly limit: number; readonly windowSeconds: number };
}

/** Logging in through upstream IdPs, at a public origin. */
export interface FederationPart {
	readonly origin: string;
	readonly idps: readonly IdpScene[];
	/** Where a login lands when it named no target. */
	readonly landing: string;
	/** Where a login may return to. */
	readonly returnTargets: readonly string[];
	/** The deployment keeps the upstream tokens of logins and hands them to receiving clients. */
	readonly keepsUpstreamTokens?: boolean;
	/** The deployment holds upstream credentials for clients, as federation grants. */
	readonly grants?: GrantsPart;
	/** The scene links an upstream identity to the account logged in, from the deployment's own page. */
	readonly links?: boolean;
}

export const federationArea = area<FederationPart>("federation");

/** A federation scene, in the shape the scenes write it. */
export interface FederationScene extends FederationPart {
	readonly keys?: KeysPart;
	readonly users: readonly UserScene[];
	/** Clients that run the code flow, so a scene can ask whether a browser is logged in. */
	readonly clients?: readonly ClientScene[];
	readonly userinfo?: boolean;
	readonly revocations?: RevocationScene;
}

export function federationScene(scene: FederationScene): AreaScene {
	return sceneOf(
		...(scene.keys ? [keysArea.part(scene.keys)] : []),
		identityArea.part({
			origin: scene.origin,
			users: scene.users,
			login: { returnTargets: scene.returnTargets },
			...(scene.revocations ? { revocations: scene.revocations } : {}),
		}),
		...(scene.clients
			? [
					oauthArea.part({ issuer: scene.origin, clients: scene.clients }),
					// Receiving clients refresh their own tokens.
					codeArea.part({
						...(scene.keepsUpstreamTokens ? { refresh: {} } : {}),
						...(scene.userinfo ? { userinfo: true } : {}),
					}),
				]
			: []),
		federationArea.part({
			origin: scene.origin,
			idps: scene.idps,
			landing: scene.landing,
			returnTargets: scene.returnTargets,
			...(scene.keepsUpstreamTokens ? { keepsUpstreamTokens: true } : {}),
			...(scene.grants ? { grants: scene.grants } : {}),
			...(scene.links ? { links: true } : {}),
		}),
	);
}
