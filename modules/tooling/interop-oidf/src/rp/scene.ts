import { generateKeyPairSync } from "node:crypto";
import { type AreaScene, area, onNew } from "@mod/conformance";
import { federationScene } from "@mod/conformance-federation";
import type { ClientScene } from "@mod/conformance-oauth";

/** The IdP the suite plays, by its name in the app's settings and its start's path. */
export const idpName = "oidf";

/** The subject the suite's OP tells for its one user (its `OIDCCLoadUserInfo`). */
export const suiteSubject = "user-subject-1234531";

/** The client the harness asks, silently, whether a browser is logged in and as whom. */
export const probe = {
	id: "probe",
	secret: "probe-secret-0123456789abcdef",
	redirectUri: "https://probe.invalid/callback",
} as const;

/** What the harness asks of the app beyond the areas' scenes: the way out to the suite, and its limits. */
interface RpPart {
	readonly proxy: string;
}

const rpArea = area<RpPart>("interop-oidf-rp");

const perSource = 1000; // a whole plan's requests come from the harness alone

onNew(rpArea, (part) => ({
	config: {
		// The suite's host resolves to loopback, which outbound never reaches over https but by a proxy.
		outbound: { proxy: part.proxy },
		federation: { requests: perSource },
		authorize: { requests: perSource },
		"token-endpoint": { requests: perSource },
	},
}));

/** The local user the suite's subject is linked to. */
export interface RpUser {
	readonly identifier: string;
	readonly subject: string;
}

/**
 * The provider as the suite's RP plan meets it, behind the front at `origin`: a federation login
 * through one OpenID Connect IdP reading UserInfo, the suite's OP at `issuer`, reached through the CONNECT proxy at
 * `proxy`; the suite's subject linked to one local user; and a first-party client to probe a
 * browser's login with.
 */
export function rpScene(given: {
	readonly origin: string;
	readonly issuer: string;
	readonly client: { readonly id: string; readonly secret: string };
	readonly user: RpUser;
	readonly proxy: string;
	/** Where a login returns to: never followed, the harness reads where it was sent. */
	readonly returnTarget: string;
	readonly readUserinfo: boolean;
}): AreaScene {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const probeClient: ClientScene = {
		id: probe.id,
		kind: "confidential",
		method: "client_secret_post",
		secret: probe.secret,
		grants: ["authorization_code"],
		scopes: ["openid"],
		redirectUris: [probe.redirectUri],
		firstParty: true,
	};
	const scene = federationScene({
		origin: given.origin,
		keys: {
			signing: {
				kid: `oidf-rp-${Date.now().toString(36)}`,
				alg: "RS256",
				privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
				publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
			},
		},
		idps: [
			{
				name: idpName,
				issuer: given.issuer,
				clientId: given.client.id,
				clientSecret: given.client.secret,
				readUserinfo: given.readUserinfo,
				scopes: ["openid", "profile", "email"],
			},
		],
		landing: given.returnTarget,
		returnTargets: [given.returnTarget],
		users: [
			{
				identifier: given.user.identifier,
				password: "unused-0123456789abcdef",
				subject: given.user.subject,
				upstream: { idp: idpName, subject: suiteSubject },
			},
		],
		clients: [probeClient],
	});
	return { ...scene, parts: { ...scene.parts, [rpArea.name]: { proxy: given.proxy } } };
}
