import { generateKeyPairSync, randomBytes, scryptSync } from "node:crypto";
import { type AreaScene, area, onNew } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";

/** A scrypt hash in the users' form, with the least work it takes: the password is a test's. */
function scryptHash(password: string): string {
	const salt = randomBytes(16);
	const key = scryptSync(password, salt, 32, { N: 2 ** 10, r: 8, p: 1 });
	const b64 = (bytes: Buffer) => bytes.toString("base64").replace(/=+$/, "");
	return `$scrypt$ln=10,r=8,p=1$${b64(salt)}$${b64(key)}`;
}

/** The person the suite's browser logs in as, with every claim the provider's table can release. */
export interface SuiteUser {
	readonly identifier: string;
	readonly password: string;
	readonly name: string;
	readonly email: string;
	readonly picture: string;
}

/** What the harness asks of the app beyond the areas' scenes: one source's limits and the user's claims. */
interface HarnessPart {
	readonly user: SuiteUser;
}

const harnessArea = area<HarnessPart>("interop-oidf");

/** Requests from the one source a suite run comes from, per window: a whole plan's. */
const perSource = 1000;

onNew(harnessArea, (part) => ({
	config: {
		authorize: { requests: perSource },
		"token-endpoint": { requests: perSource },
		"token-control": { requests: perSource },
		"login-password": { attempts: 100, window: "1m" },
		// The identity area's users, with the claims it has no field for.
		users: {
			registered: [
				{
					identifier: part.user.identifier,
					"password-hash": scryptHash(part.user.password),
					attributes: {
						name: part.user.name,
						email: part.user.email,
						email_verified: true,
						picture: part.user.picture,
					},
				},
			],
		},
	},
}));

/** A client the suite's plans name, as their configuration does. */
export interface SuiteClient {
	readonly id: string;
	readonly secret: string;
	readonly method: "client_secret_basic" | "client_secret_post";
}

/** An RS256 signing key of this run's own: the algorithm the suite's plans take. */
function signing() {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return {
		kid: `oidf-${Date.now().toString(36)}`,
		alg: "RS256" as const,
		privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

/**
 * The provider the suite's OP plans meet, behind the front at `origin`: the code flow with
 * discovery, userinfo and refresh, first-party clients whose redirect URIs are the suite's
 * callbacks under `alias`, and one user.
 */
export function suiteScene(given: {
	readonly origin: string;
	readonly suite: string;
	readonly alias: string;
	readonly clients: readonly SuiteClient[];
	readonly user: SuiteUser;
}): AreaScene {
	const callback = `${given.suite}/test/a/${given.alias}/callback`;
	const scene = codeScene({
		issuer: given.origin,
		keys: { signing: signing() },
		users: [{ identifier: given.user.identifier, password: given.user.password }],
		clients: given.clients.map((c) => ({
			id: c.id,
			kind: "confidential" as const,
			method: c.method,
			secret: c.secret,
			grants: ["authorization_code", "refresh_token"],
			scopes: ["openid", "profile", "email"],
			redirectUris: [callback],
			firstParty: true,
		})),
		discovery: true,
		userinfo: true,
		refresh: {},
	});
	return { ...scene, parts: { ...scene.parts, [harnessArea.name]: { user: given.user } } };
}
