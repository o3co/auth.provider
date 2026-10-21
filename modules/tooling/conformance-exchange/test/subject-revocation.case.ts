import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { type AreaScene, areaTarget, type Fake, fakeHttp, type Started } from "@mod/conformance";
import { codeScene } from "@mod/conformance-code";
import { browserAt } from "@mod/conformance-code/testing";
import { deviceArea } from "@mod/conformance-device";
import { ledgerRevocation } from "@mod/conformance-identity";
import type { ClientScene } from "@mod/conformance-oauth";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { exchangeArea } from "../src/main.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const api = "https://api.example";
const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const accessType = "urn:ietf:params:oauth:token-type:access_token";
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code";
const credential = randomBytes(32).toString("base64url");
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const secretOf = (id: string) => `${id}-secret-0123456789abcdef`;
const user = { username: "alice", password: "correct horse battery" };
const subject = "user-alice";

/** The parts a revocation has to reach: a code with refresh and exchange, a device's, and a logout told by the back channel. */
function sceneTold(backChannelBase: string): AreaScene {
	const app: ClientScene = {
		id: "app",
		kind: "confidential",
		method: "client_secret_post",
		secret: secretOf("app"),
		grants: ["authorization_code", "refresh_token", exchangeGrant],
		scopes: ["openid", "read"],
		defaultScopes: ["read"],
		redirectUris: [callback],
		firstParty: true,
		audiences: [api],
		logout: { backchannelLogoutUri: `${backChannelBase}/bc` },
	};
	const tv: ClientScene = {
		id: "tv",
		kind: "confidential",
		method: "client_secret_post",
		secret: secretOf("tv"),
		grants: [deviceGrant],
		scopes: ["read"],
		defaultScopes: ["read"],
		audiences: [api],
	};
	const built = codeScene({
		issuer,
		keys: {
			signing: {
				kid: "sr",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [app, tv],
		users: [{ identifier: user.username, password: user.password, subject }],
		refresh: {},
		introspection: true,
		revocations: { credential, sources: ["198.51.100.0/24"] },
		logout: { allowed: [backChannelBase] },
	});
	const [exchange, exchangePart] = exchangeArea.part({});
	const [device, devicePart] = deviceArea.part({ verificationUri: `${issuer}/device` });
	return { ...built, parts: { ...built.parts, [exchange]: exchangePart, [device]: devicePart } };
}

let told: Fake;
let running: Started;
let base = "";

const browser = browserAt(() => base, issuer, user);
/** What the deployment's proxy adds to a client's own call. */
const backChannel = { "x-forwarded-proto": "https", "x-forwarded-for": "198.51.100.21" };
async function post(path: string, as: string, form: Record<string, string>) {
	const res = await fetch(`${base}${path}`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ ...form, client_id: as, client_secret: secretOf(as) }),
	});
	const text = await res.text();
	return { status: res.status, body: (text ? JSON.parse(text) : {}) as Record<string, string> };
}
const refusal = (answer: { status: number; body: Record<string, string> }) => [
	answer.status,
	answer.body.error,
];
const active = async (token: string | undefined) =>
	(await post("/oauth/introspect", "app", { token: token ?? "" })).body.active;
const claimsOf = (jwt: string | undefined) =>
	JSON.parse(Buffer.from((jwt ?? "").split(".")[1] ?? "", "base64url").toString());
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** The authorization request of the app, silent where `prompt` says. */
const codeRequest = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s",
	scope: "openid read",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});
const codeOf = async () =>
	(await browser.authorize(codeRequest())).at?.searchParams.get("code") ?? "";
const redeem = (code: string) =>
	post("/oauth/token", "app", {
		grant_type: "authorization_code",
		code,
		redirect_uri: callback,
		code_verifier: verifier,
	});
const exchange = (token: string | undefined) =>
	post("/oauth/token", "app", {
		grant_type: exchangeGrant,
		subject_token: token ?? "",
		subject_token_type: accessType,
	});
const poll = (deviceCode: string) =>
	post("/oauth/token", "tv", { grant_type: deviceGrant, device_code: deviceCode });
/** A device's codes, approved by the browser's session through the deployment's page. */
async function approvedDevice() {
	const given = await post("/oauth/device_authorization", "tv", {});
	const res = await fetch(`${base}/oauth/device/verification`, {
		method: "POST",
		headers: browser.headers({
			"content-type": "application/json",
			origin: issuer,
			cookie: await browser.login(),
		}),
		body: JSON.stringify({ action: "approve", user_code: given.body.user_code }),
	});
	expect(res.status).toBe(200);
	return given.body.device_code ?? "";
}
/** The ledger's revocation of a subject, from its block over https, as its proxy forwards it. */
async function revoke(revoked: string) {
	const res = await fetch(`${base}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject: revoked }),
	});
	return { status: res.status, json: await res.json() };
}

describe.runIf(areaTarget().can(ledgerRevocation))(
	"a subject the ledger revokes: every way to a token",
	() => {
		beforeAll(async () => {
			told = await fakeHttp(() => ({ status: 200 }));
			running = await areaTarget().start(sceneTold(told.base));
			if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await told?.stop();
		});

		it("refuses what was issued or begun before it, tells the session's client, and takes a fresh login", async () => {
			const tokens = (await redeem(await codeOf())).body;
			const unredeemed = await codeOf();
			const exchanged = await exchange(tokens.access_token);
			expect(exchanged.status).toBe(200);
			const polled = await poll(await approvedDevice());
			expect(polled.status).toBe(200);
			const unpolled = await approvedDevice();
			const issued = [tokens.access_token, exchanged.body.access_token, polled.body.access_token];
			for (const token of issued) expect(await active(token)).toBe(true);

			const before = told.received.length;
			expect(await revoke(subject)).toEqual({ status: 200, json: { complete: true } });

			// The session closed, so its client is told by a logout token naming it.
			for (let i = 0; i < 100 && told.received.length === before; i++) await wait(50);
			const notice = told.received[before];
			expect([notice?.method, notice?.path]).toEqual(["POST", "/bc"]);
			const logoutToken = new URLSearchParams(notice?.body).get("logout_token") ?? "";
			expect(claimsOf(logoutToken)).toMatchObject({
				iss: issuer,
				aud: "app",
				sid: claimsOf(tokens.id_token).sid,
			});
			expect(Object.keys(claimsOf(logoutToken).events)).toEqual([
				"http://schemas.openid.net/event/backchannel-logout",
			]);

			// The browser's session no longer lets its user in: the authorization endpoint asks for a login.
			const silent = await browser.authorize(codeRequest({ prompt: "none" }));
			expect(silent.at?.searchParams.get("error")).toBe("login_required");
			const asked = await browser.authorize(codeRequest());
			expect(asked.at ? asked.at.origin + asked.at.pathname : "").toBe(`${issuer}/login`);
			expect(asked.at?.searchParams.get("redirect_to")).toBeTruthy();

			// Nothing begun or issued before it gives or keeps a token.
			expect(refusal(await redeem(unredeemed))).toEqual([400, "invalid_grant"]);
			const refreshed = await post("/oauth/token", "app", {
				grant_type: "refresh_token",
				refresh_token: tokens.refresh_token ?? "",
			});
			expect(refusal(refreshed)).toEqual([400, "invalid_grant"]);
			expect(refusal(await poll(unpolled))).toEqual([400, "invalid_grant"]);
			for (const token of issued) expect(await active(token)).toBe(false);
			expect(refusal(await exchange(tokens.access_token))).toEqual([400, "invalid_request"]);

			// A login after the boundary's second is past it, and lets the user in again.
			await wait(1100);
			browser.forget();
			const again = await browser.authorize(codeRequest({ prompt: "none" }));
			expect(again.at?.searchParams.get("code")).toBeTruthy();
		}, 30_000);
	},
);
