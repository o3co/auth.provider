import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AreaScene } from "@mod/conformance";
import type { Instance } from "@mod/conformance/testing";
import { selfSigned, startFront } from "@mod/conformance-front";
import { startTunnel } from "@mod/conformance-tunnel";
import { exportJWK, SignJWT } from "jose";
import { type Answer, app, exchangeGrant, faultScene, postAt, users } from "./faults.ts";

// Apple's issuer and key set are fixed by exchange-id-tokens, never settings: the app reaches Apple's
// own host, through a tunnel to a front that answers its key set under a certificate the app trusts.

const host = "appleid.apple.com";
const bearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const idTokenType = "urn:ietf:params:oauth:token-type:id_token";
/** The app's client ID at Apple: the audience of the id_tokens it is given there. */
const audience = "com.example.app";
/** alice's subject at Apple, which her account is linked to. */
const subject = "apple-alice";
const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
const kid = "apple-faults";

/** Apple's host as the app reaches it: the proxy its outbound goes through, and the certificate to trust. */
export interface Apple {
	readonly proxy: string;
	readonly trusted: string;
	stop(): Promise<void>;
}

/** Apple's key set at its own host on https: a front answering it, and a tunnel to the front alone. */
export async function startApple(): Promise<Apple> {
	const dir = await mkdtemp(join(tmpdir(), "exchange-apple-"));
	const tls = await selfSigned(host, dir);
	const trusted = join(dir, "trusted.pem");
	await writeFile(trusted, tls.cert);
	const keys = { keys: [{ ...(await exportJWK(key.publicKey)), kid, alg: "RS256", use: "sig" }] };
	const front = await startFront({
		// The front answers every request itself: nothing goes on.
		upstream: () => "http://127.0.0.1:1",
		publicHost: host,
		listen: "127.0.0.1",
		tls,
		handle: (request) =>
			request.method === "GET" && request.url.pathname === "/auth/keys"
				? {
						status: 200,
						headers: { "content-type": "application/json" },
						body: JSON.stringify(keys),
					}
				: { status: 404 },
	});
	const tunnel = await startTunnel({
		allow: { [`${host}:443`]: `127.0.0.1:${new URL(front.origin).port}` },
	});
	return {
		proxy: `http://127.0.0.1:${tunnel.port}`,
		trusted,
		stop: async () => {
			await tunnel.stop();
			await front.stop();
			await rm(dir, { recursive: true, force: true });
		},
	};
}

/** The fault scene with `app` taking Apple's id_tokens by both grants, and alice linked at Apple. */
export const appleScene = (apple: Apple): AreaScene =>
	faultScene(
		{
			clients: [{ ...app, grants: [...app.grants, bearerGrant] }],
			users: [
				{
					identifier: users.alice.username,
					password: users.alice.password,
					subject: users.alice.subject,
					upstream: { idp: "apple", subject },
				},
			],
		},
		{ appleIdTokens: { clients: { [app.id]: [audience] }, proxy: apple.proxy } },
	);

/** An id_token Apple signs for alice to the app, made one of its own by a random claim. */
export async function idToken(): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	return new SignJWT({ n: randomUUID() })
		.setProtectedHeader({ alg: "RS256", kid })
		.setIssuer("https://appleid.apple.com")
		.setSubject(subject)
		.setAudience(audience)
		.setIssuedAt(now)
		.setExpirationTime(now + 600)
		.sign(key.privateKey);
}

/** The id_token exchanged by `app` at the instance, as the subject token. */
export const exchangedAt = (i: Instance, token: string): Promise<Answer> =>
	postAt(i, "/oauth/token", {
		grant_type: exchangeGrant,
		subject_token: token,
		subject_token_type: idTokenType,
	});

/** The id_token sent by `app` to the instance as a JWT bearer assertion. */
export const assertedAt = (i: Instance, token: string): Promise<Answer> =>
	postAt(i, "/oauth/token", { grant_type: bearerGrant, assertion: token });
