import { type AreaScene, area, sceneOf } from "@mod/conformance";
import {
	identityArea,
	type LedgerScene,
	type RevocationScene,
	type UserScene,
} from "@mod/conformance-identity";
import { type KeysPart, keysArea } from "@mod/conformance-keys";
import { type MtlsPart, mtlsArea } from "@mod/conformance-mtls";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";
import { secondFactorArea } from "@mod/conformance-second-factor";

/** The authorization code flow (RFC 6749 §4.1) with PKCE, for the clients that have redirect URIs. */
export interface CodePart {
	/** Leaves the consent step out, so a client that is not first-party cannot be asked. */
	readonly withoutConsent?: boolean;
	/** Refresh tokens (RFC 6749 §6) with the code, for the clients allowed the refresh grant. */
	readonly refresh?: { readonly lifetimeSeconds?: number };
	/** Modules the scene is about the absence of: a pattern composing one cannot hold it. */
	readonly without?: readonly string[];
	/** Each acr and the amr sets that meet it; where second factors are on, a session can be sent to raise them. */
	readonly acr?: { readonly values: Readonly<Record<string, readonly (readonly string[])[]>> };
	/** The grant `session`: an access token for the user of the browser's session, for the clients allowed it. */
	readonly sessionGrant?: boolean;
	/** Clients whose id is the URL of their metadata document, under the operator's hosts and scopes. */
	readonly documents?: {
		readonly allow?: readonly string[];
		readonly deny?: readonly string[];
		readonly scopes?: readonly string[];
	};
	/** A logout a client starts (OpenID Connect RP-Initiated Logout 1.0), with the clients' channels; only the `allowed` origins are reached on the back channel. */
	readonly logout?: { readonly allowed: readonly string[] };
	/** OpenID Connect's userinfo, answering an access token's subject and claims. */
	readonly userinfo?: boolean;
	/** Tokens bound by DPoP presented at resources: on the legacy build, its DPoP package, which the oauth area does not set up. */
	readonly dpopAtResources?: boolean;
	/** How often each host goes on with pending closes of a session, in seconds; a fault scene's own. */
	readonly sweepSeconds?: number;
}

export const codeArea = area<CodePart>("code");

/** A code-flow scene, in the shape the scenes write it. */
export interface CodeScene extends CodePart {
	readonly issuer: string;
	readonly keys?: KeysPart;
	readonly clients: readonly ClientScene[];
	readonly users: readonly UserScene[];
	/** Users answered from a ledger over HTTP. */
	readonly ledger?: LedgerScene;
	readonly login?: { readonly returnTargets?: readonly string[] };
	readonly corsOrigins?: readonly string[];
	/** Subjects the ledger revokes over HTTP, as the identity area sets it up. */
	readonly revocations?: RevocationScene;
	readonly introspection?: boolean;
	readonly revocation?: boolean;
	readonly dpop?: boolean;
	/** Resource indicators (RFC 8707), as the oauth area sets them up. */
	readonly resourceIndicators?: boolean;
	/** The provider's metadata document. */
	readonly discovery?: boolean;
	readonly mfa?: { readonly mode: "optional" | "required" };
	readonly storeFaults?: boolean;
	/** Tokens bound to the client's certificate, as the mTLS area sets each target up. */
	readonly mtls?: MtlsPart;
	/** No token for a user whose account does not state the email verified, as the OAuth area sets it up. */
	readonly verifiedEmail?: true;
}

export function codeScene(scene: CodeScene): AreaScene {
	const built = sceneOf(
		...(scene.keys ? [keysArea.part(scene.keys)] : []),
		identityArea.part({
			origin: scene.issuer,
			users: scene.users,
			...(scene.ledger ? { ledger: scene.ledger } : {}),
			...(scene.login ? { login: scene.login } : {}),
			...(scene.corsOrigins ? { corsOrigins: scene.corsOrigins } : {}),
			...(scene.revocations ? { revocations: scene.revocations } : {}),
		}),
		oauthArea.part({
			issuer: scene.issuer,
			clients: scene.clients,
			...(scene.introspection ? { introspection: true } : {}),
			...(scene.revocation ? { revocation: true } : {}),
			...(scene.dpop ? { dpop: true } : {}),
			...(scene.resourceIndicators ? { resourceIndicators: true } : {}),
			...(scene.discovery ? { discovery: true } : {}),
			...(scene.verifiedEmail ? { verifiedEmail: true } : {}),
		}),
		...(scene.mfa ? [secondFactorArea.part(scene.mfa)] : []),
		...(scene.mtls ? [mtlsArea.part(scene.mtls)] : []),
		codeArea.part({
			...(scene.withoutConsent ? { withoutConsent: true } : {}),
			...(scene.refresh ? { refresh: scene.refresh } : {}),
			...(scene.acr ? { acr: scene.acr } : {}),
			...(scene.without ? { without: scene.without } : {}),
			...(scene.sessionGrant ? { sessionGrant: true } : {}),
			...(scene.documents ? { documents: scene.documents } : {}),
			...(scene.logout ? { logout: scene.logout } : {}),
			...(scene.userinfo ? { userinfo: true } : {}),
			...(scene.dpopAtResources ? { dpopAtResources: true } : {}),
			...(scene.sweepSeconds ? { sweepSeconds: scene.sweepSeconds } : {}),
		}),
	);
	return scene.storeFaults ? { ...built, storeFaults: true } : built;
}
