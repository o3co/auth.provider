import { type AreaScene, area, sceneOf } from "@mod/conformance";
import { identityArea, type RevocationScene, type UserScene } from "@mod/conformance-identity";
import { type KeysPart, keysArea } from "@mod/conformance-keys";
import { type ClientScene, oauthArea } from "@mod/conformance-oauth";

/** The Device Authorization Grant (RFC 8628), for the clients allowed it. */
export interface DevicePart {
	/** The deployment's page where a user enters the code. */
	readonly verificationUri: string;
	/** Decisions a subject may try in each window. */
	readonly attempts?: number;
}

export const deviceArea = area<DevicePart>("device");

/** A device scene, in the shape the scenes write it. */
export interface DeviceScene extends DevicePart {
	readonly issuer: string;
	readonly keys?: KeysPart;
	readonly clients: readonly ClientScene[];
	readonly users: readonly UserScene[];
	/** No token for a user whose account does not state the email verified, as the OAuth area sets it up. */
	readonly verifiedEmail?: true;
	/** Subjects the ledger revokes over HTTP, as the identity area sets it up. */
	readonly revocations?: RevocationScene;
}

export function deviceScene(scene: DeviceScene): AreaScene {
	return sceneOf(
		...(scene.keys ? [keysArea.part(scene.keys)] : []),
		identityArea.part({
			origin: scene.issuer,
			users: scene.users,
			...(scene.revocations ? { revocations: scene.revocations } : {}),
		}),
		oauthArea.part({
			issuer: scene.issuer,
			clients: scene.clients,
			...(scene.verifiedEmail ? { verifiedEmail: true } : {}),
		}),
		deviceArea.part({
			verificationUri: scene.verificationUri,
			...(scene.attempts ? { attempts: scene.attempts } : {}),
		}),
	);
}
