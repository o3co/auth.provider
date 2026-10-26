import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { FlattenedSign, type JWTPayload, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { oauthScene } from "../src/main.ts";

const issuer = "https://issuer.example";
const tokenUrl = `${issuer}/oauth/token`;
const signing = generateKeyPairSync("ed25519");
const clientKey = generateKeyPairSync("ec", { namedCurve: "P-256" });
const scene = oauthScene({
	issuer,
	keys: {
		signing: {
			kid: "ca",
			alg: "EdDSA",
			privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "app",
			kind: "confidential",
			method: "private_key_jwt",
			keys: [{ ...clientKey.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }],
			grants: ["client_credentials"],
			scopes: ["read"],
			defaultScopes: ["read"],
		},
		{
			id: "loose",
			kind: "confidential",
			method: "private_key_jwt",
			keys: [{ ...clientKey.publicKey.export({ format: "jwk" }), kid: "k1", use: "sig" }],
			looseAudience: true,
			grants: ["client_credentials"],
			scopes: ["read"],
			defaultScopes: ["read"],
		},
	],
	introspection: true,
	revocation: true,
});

let running: Started;
let base = "";
beforeAll(async () => {
	running = await areaTarget().start(scene);
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
});

const type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const now = () => Math.floor(Date.now() / 1000);
/** The claims of a good assertion, changed as given; a claim given as undefined is left out. */
const claims = (extra: Record<string, unknown> = {}): JWTPayload =>
	Object.fromEntries(
		Object.entries({
			iss: "app",
			sub: "app",
			aud: issuer,
			exp: now() + 60,
			iat: now(),
			jti: `j-${Math.random()}`,
			...extra,
		}).filter(([, value]) => value !== undefined),
	);
const sign = (payload: JWTPayload, key: KeyObject = clientKey.privateKey, alg = "ES256") =>
	new SignJWT(payload).setProtectedHeader({ alg, kid: "k1" }).sign(key);
async function post(path: string, form: Record<string, string>, headers = {}) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
		body: new URLSearchParams(form),
	});
	return {
		status: res.status,
		body: (await res.json()) as Record<string, unknown>,
		challenge: res.headers.get("www-authenticate"),
	};
}
const token = async (assertion: string, extra: Record<string, string> = {}) =>
	post("/oauth/token", {
		grant_type: "client_credentials",
		client_assertion_type: type,
		client_assertion: assertion,
		...extra,
	});
const refused = async (answer: Promise<{ status: number; body: Record<string, unknown> }>) => {
	const { status, body } = await answer;
	return [status, body.error];
};

describe("client authentication by private_key_jwt", () => {
	it("authenticates a client by an assertion signed with its key, for the issuer", async () => {
		expect((await token(await sign(claims()))).status).toBe(200);
		expect((await token(await sign(claims()), { client_id: "app" })).status).toBe(200);
	});

	it.skipIf(areaTarget().differs("assertion-audience-beside-issuer"))(
		"refuses an assertion for the token endpoint, or naming its audience in a list, and spends none",
		async () => {
			const jti = `j-${Math.random()}`;
			for (const aud of [tokenUrl, [issuer], ["x", issuer], [issuer, tokenUrl]]) {
				expect(await refused(token(await sign(claims({ aud, jti })))), JSON.stringify(aud)).toEqual(
					[401, "invalid_client"],
				);
			}
			expect((await token(await sign(claims({ jti })))).status).toBe(200);
		},
	);

	it("takes an assertion for the token endpoint, or naming its audience in a list, from a client accepting a loose audience", async () => {
		const loose = (aud: unknown) => sign(claims({ iss: "loose", sub: "loose", aud }));
		for (const aud of [tokenUrl, [tokenUrl], ["x", issuer], issuer]) {
			expect((await token(await loose(aud))).status, JSON.stringify(aud)).toBe(200);
		}
		expect(await refused(token(await loose(`${issuer}/other`)))).toEqual([401, "invalid_client"]);
	});

	it("authenticates a client at introspection too", async () => {
		const issued = await token(await sign(claims()));
		const ask = async (key?: KeyObject) =>
			post("/oauth/introspect", {
				token: String(issued.body.access_token),
				client_assertion_type: type,
				client_assertion: await sign(claims(), key),
			});
		expect((await ask()).status).toBe(200);
		const stranger = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
		expect(await refused(ask(stranger))).toEqual([401, "invalid_client"]);
	});

	it("refuses an assertion for another audience, too long-lived, expired, or of another issuer", async () => {
		const wrong = [401, "invalid_client"];
		expect(await refused(token(await sign(claims({ aud: `${issuer}/other` }))))).toEqual(wrong);
		expect(await refused(token(await sign(claims({ exp: now() + 7200 }))))).toEqual(wrong);
		expect(await refused(token(await sign(claims({ exp: now() - 120 }))))).toEqual(wrong);
		expect(await refused(token(await sign(claims({ sub: "other" }))))).toEqual(wrong);
		expect(await refused(token(await sign(claims()), { client_id: "other" }))).toEqual(wrong);
	});

	it("takes each assertion once", async () => {
		const once = await sign(claims());
		expect((await token(once)).status).toBe(200);
		expect(await refused(token(once))).toEqual([401, "invalid_client"]);
	});

	it("refuses a symmetric algorithm and a key that is not the client's", async () => {
		const hmac = await new SignJWT(claims())
			.setProtectedHeader({ alg: "HS256", kid: "k1" })
			.sign(new Uint8Array(32));
		expect(await refused(token(hmac))).toEqual([401, "invalid_client"]);
		const stranger = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
		expect(await refused(token(await sign(claims(), stranger)))).toEqual([401, "invalid_client"]);
	});

	it.skipIf(areaTarget().differs("assertion-with-secret"))(
		"refuses an assertion sent beside a client secret as invalid_client [rfc7521-4.2.1-b]",
		async () => {
			expect(await refused(token(await sign(claims()), { client_secret: "x" }))).toEqual([
				401,
				"invalid_client",
			]);
		},
	);

	it("refuses an assertion of a type it does not take, whatever else the request carries", async () => {
		const answer = await post("/oauth/token", {
			grant_type: "client_credentials",
			client_assertion_type: "urn:unsupported",
			client_assertion: await sign(claims()),
		});
		expect([answer.status, answer.body.error]).toEqual([401, "invalid_client"]);
	});

	it("refuses an assertion given twice as invalid_client, and spends neither [rfc7521-4.2.1-a]", async () => {
		const [first, second] = [await sign(claims()), await sign(claims())];
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams([
				["grant_type", "client_credentials"],
				["client_assertion_type", type],
				["client_assertion", first],
				["client_assertion", second],
			]),
		});
		expect([res.status, ((await res.json()) as { error: string }).error]).toEqual([
			401,
			"invalid_client",
		]);
		expect((await token(first)).status).toBe(200);
	});

	it("refuses an assertion with an unencoded payload", async () => {
		const flat = await new FlattenedSign(new TextEncoder().encode(JSON.stringify(claims())))
			.setProtectedHeader({ alg: "ES256", kid: "k1", b64: false, crit: ["b64"] })
			.sign(clientKey.privateKey);
		const unencoded = `${flat.protected}.${flat.payload}.${flat.signature}`;
		expect(await refused(token(unencoded, { client_id: "app" }))).toEqual([401, "invalid_client"]);
	});

	it("refuses half of an assertion as invalid_client [rfc7521-4.2.1-a]", async () => {
		const malformed = [401, "invalid_client"];
		expect(
			await refused(
				post("/oauth/token", { grant_type: "client_credentials", client_assertion_type: type }),
			),
		).toEqual(malformed);
		expect(
			await refused(
				post("/oauth/token", {
					grant_type: "client_credentials",
					client_assertion: await sign(claims()),
				}),
			),
		).toEqual(malformed);
	});

	it("refuses an assertion beside another client authentication method as invalid_client, challenging for Basic where the request used it, at the token, introspection and revocation endpoints [rfc7521-4.2.1-b]", async () => {
		const issued = String((await token(await sign(claims()))).body.access_token);
		const basic = { authorization: `Basic ${Buffer.from("app:a-secret").toString("base64")}` };
		const endpoints: [string, Record<string, string>][] = [
			["/oauth/token", { grant_type: "client_credentials" }],
			["/oauth/introspect", { token: issued }],
			["/oauth/revoke", { token: issued }],
		];
		for (const [path, form] of endpoints) {
			const beside = async (extra: Record<string, string> = {}) => ({
				...form,
				client_assertion_type: type,
				client_assertion: await sign(claims()),
				...extra,
			});
			const byHeader = await post(path, await beside(), basic);
			expect([byHeader.status, byHeader.body.error, byHeader.challenge], path).toEqual([
				401,
				"invalid_client",
				'Basic realm="client"',
			]);
			const byBody = await post(
				path,
				await beside({ client_id: "app", client_secret: "a-secret" }),
			);
			expect([byBody.status, byBody.body.error], path).toEqual([401, "invalid_client"]);
		}
	});
});
