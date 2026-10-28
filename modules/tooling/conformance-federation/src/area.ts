import { type AreaScene, area, sceneOf } from "@mod/conformance";
import { codeArea } from "@mod/conformance-code";
import {
	identityArea,
	type LedgerScene,
	type RevocationScene,
	type UserScene,
} from "@mod/conformance-identity";
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
	/** OpenID Connect only: reads UserInfo after each login (`readsUserinfo`). */
	readonly readUserinfo?: boolean;
	/** OpenID Connect only: the scopes asked of the upstream at a login, `openid` among them. */
	readonly scopes?: readonly string[];
	/** OpenID Connect only: hosts besides the issuer's its described endpoints may be on. */
	readonly endpointHosts?: readonly string[];
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

/** The need for a login page that a connect sends a browser with no session to, and back. */
export const grantsLoginPage = "federation:grants-login-page";

/** The need for a step-up page that a link's start short of a requirement names, and back. */
export const linkStepUpPage = "federation:link-step-up-page";

/** The need for an OpenID Connect IdP that reads its upstream's UserInfo after each login. */
export const readsUserinfo = "federation:reads-userinfo";

/** Federation grants: the consent page and the connections offered. */
export interface GrantsPart {
	readonly page: string;
	/** Where a browser with no session is sent to log in, then back to the connect (`grantsLoginPage`). */
	readonly loginPage?: string;
	readonly connections: readonly ConnectionScene[];
	/** How many intents one client may lodge in a window, whatever user it names. */
	readonly lodges?: { readonly limit: number; readonly windowSeconds: number };
	/** A revocation that asks to keep delegations leaves established grants to the `delegations` boundary alone. */
	readonly keepOnSubjectRevocation?: boolean;
}

/** Logging in through upstream IdPs, at a public origin. */
export interface FederationPart {
	readonly origin: string;
	readonly idps: readonly IdpScene[];
	/** Where a login lands when it named no target; the origin's root without one. */
	readonly landing?: string;
	/** Where a login may return to. */
	readonly returnTargets: readonly string[];
	/** The page a browser goes on at when a gate holds its login, on the origin. */
	readonly heldPage?: string;
	/** The deployment keeps the upstream tokens of logins and hands them to receiving clients. */
	readonly keepsUpstreamTokens?: boolean;
	/** The deployment holds upstream credentials for clients, as federation grants. */
	readonly grants?: GrantsPart;
	/** The scene links an upstream identity to the account logged in, from the deployment's own page. */
	readonly links?: boolean;
	/** The page a link's start short of a session requirement names, on the origin (`linkStepUpPage`). */
	readonly linkStepUpPage?: string;
	/** A CONNECT proxy outbound reaches its upstreams through, for an upstream on https at loopback. */
	readonly proxy?: string;
	/** The user ledger's URLs, which outbound also reaches: this part's outbound section is the one kept. */
	readonly ledgerUrls?: readonly string[];
	/** Modules the scene is about the absence of: a pattern composing one cannot hold it. */
	readonly without?: readonly string[];
}

export const federationArea = area<FederationPart>("federation");

/** A federation scene, in the shape the scenes write it. */
export interface FederationScene extends FederationPart {
	readonly keys?: KeysPart;
	readonly users: readonly UserScene[];
	/** Users answered from a ledger over HTTP, beside or instead of `users`. */
	readonly ledger?: LedgerScene;
	/** Clients that run the code flow, so a scene can ask whether a browser is logged in. */
	readonly clients?: readonly ClientScene[];
	readonly userinfo?: boolean;
	readonly revocations?: RevocationScene;
	/** How recent a sign-in a link asks, in seconds: the identity part's window. */
	readonly recentAuthenticationSeconds?: number;
}

export function federationScene(scene: FederationScene): AreaScene {
	return sceneOf(
		...(scene.keys ? [keysArea.part(scene.keys)] : []),
		identityArea.part({
			origin: scene.origin,
			users: scene.users,
			login: { returnTargets: scene.returnTargets },
			...(scene.ledger ? { ledger: scene.ledger } : {}),
			...(scene.revocations ? { revocations: scene.revocations } : {}),
			...(scene.recentAuthenticationSeconds
				? { recentAuthenticationSeconds: scene.recentAuthenticationSeconds }
				: {}),
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
			...(scene.landing ? { landing: scene.landing } : {}),
			returnTargets: scene.returnTargets,
			...(scene.heldPage ? { heldPage: scene.heldPage } : {}),
			...(scene.keepsUpstreamTokens ? { keepsUpstreamTokens: true } : {}),
			...(scene.grants ? { grants: scene.grants } : {}),
			...(scene.links ? { links: true } : {}),
			...(scene.linkStepUpPage ? { linkStepUpPage: scene.linkStepUpPage } : {}),
			...(scene.proxy ? { proxy: scene.proxy } : {}),
			...(scene.without ? { without: scene.without } : {}),
			...(scene.ledger
				? {
						ledgerUrls: [
							scene.ledger.verifyUrl,
							...(scene.ledger.upstreamUrl ? [scene.ledger.upstreamUrl] : []),
						],
					}
				: {}),
		}),
	);
}
