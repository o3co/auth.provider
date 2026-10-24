import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { areaTarget, type Fake, fakeHttp, type Started } from "@mod/conformance";
import { httpLedger } from "@mod/conformance-identity";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { backChannel, browserAt, succeeded } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const credential = randomBytes(32).toString("hex");
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid", "profile", "email"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
};
const right = { username: "alice", password: "correct horse battery" };
/** What the ledger says of alice when her password is verified. */
const alice = {
	id: "s-alice",
	username: "alice",
	email: "alice@ledger.example",
	emailVerified: true,
	name: "Alice",
	picture: "https://pictures.example/alice",
};

let fake: Fake;
let running: Started;
let base = "";
const browser = browserAt(() => base, issuer, right);

/** The ID token's claims for a code asked with `scope`, from a fresh login. */
async function idTokenClaims(scope: string): Promise<Record<string, unknown>> {
	browser.forget();
	const res = await browser.authorize({
		response_type: "code",
		client_id: app.id,
		redirect_uri: callback,
		state: "s1",
		scope,
		code_challenge: challenge,
		code_challenge_method: "S256",
	});
	const answer = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: app.id,
			client_secret: app.secret ?? "",
			code: res.at?.searchParams.get("code") ?? "",
			redirect_uri: callback,
			code_verifier: verifier,
		}),
	});
	const { id_token: token } = await succeeded(answer, "the token endpoint");
	return JSON.parse(Buffer.from(String(token).split(".")[1] ?? "", "base64url").toString());
}

describe.runIf(areaTarget().can(httpLedger))(
	"OpenID Connect: an ID token for a user from a ledger over HTTP",
	() => {
		beforeAll(async () => {
			fake = await fakeHttp(async (asked) => {
				if (asked.headers.authorization !== `Bearer ${credential}`) return { status: 401 };
				if (asked.method !== "POST" || asked.path !== "/ledger/authenticate") {
					return { status: 404 };
				}
				const { email, password } = JSON.parse(asked.body);
				if (email !== right.username) return { status: 401 };
				return password === right.password ? { json: alice } : { status: 401 };
			});
			running = await areaTarget().start(
				codeScene({
					issuer,
					keys: {
						signing: {
							kid: "lc",
							alg: "EdDSA",
							privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
							publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
						},
					},
					clients: [app],
					users: [],
					ledger: { verifyUrl: `${fake.base}/ledger/authenticate`, credential },
				}),
			);
			if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await fake?.stop();
		});

		it("carries what the ledger said at login, for the scopes asked", async () => {
			expect(await idTokenClaims("openid profile email")).toMatchObject({
				sub: "s-alice",
				aud: app.id,
				name: alice.name,
				picture: alice.picture,
				email: alice.email,
				email_verified: true,
			});
		});

		it("carries none of it for openid alone", async () => {
			const claims = await idTokenClaims("openid");
			expect(claims.sub).toBe("s-alice");
			for (const name of ["name", "picture", "email", "email_verified"]) {
				expect(claims, name).not.toHaveProperty(name);
			}
		});
	},
);
