import { createHash, generateKeyPairSync } from "node:crypto";
import { type AreaScene, areaTarget, type Started } from "@mod/conformance";
import { secondFactorArea } from "@mod/conformance-second-factor";
import {
	beginBinding,
	browser as passwordBrowser,
	totp,
} from "@mod/conformance-second-factor/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { federationScene } from "../../main.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const callback = "https://app.example/cb";
const verifier = "h".repeat(43);
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const upstreamClient = { id: "as-client", secret: "as-client-secret-0123456789" };
const receiver = { id: "fed-app", secret: "fed-app-secret-0123456789abcdef" };

// Ours holds a federation login at the login gates, as any other login.
describe.runIf(!areaTarget().differs("federation-login-held-at-gates"))(
	"federation: a login a gate holds",
	() => {
		let corp: Awaited<ReturnType<typeof fakeUpstream>>;
		let running: Started;
		let base = "";
		beforeAll(async () => {
			corp = await fakeUpstream(upstreamClient);
			const federation = federationScene({
				origin,
				keys: {
					signing: {
						kid: "held",
						alg: "EdDSA",
						privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
						publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
					},
				},
				idps: [
					{
						name: "corp",
						issuer: corp.issuer,
						clientId: upstreamClient.id,
						clientSecret: upstreamClient.secret,
					},
				],
				landing,
				returnTargets: [],
				users: [{ identifier: "alice", password, upstream: { idp: "corp", subject: "u-alice" } }],
				clients: [
					probeClient,
					{
						id: receiver.id,
						kind: "confidential",
						method: "client_secret_post",
						secret: receiver.secret,
						grants: ["authorization_code", "refresh_token"],
						scopes: ["openid", "read"],
						defaultScopes: ["read"],
						audiences: [receiver.id],
						redirectUris: [callback],
						firstParty: true,
						upstreamTokens: { postLogoutRedirectUris: [] },
					},
				],
				keepsUpstreamTokens: true,
			});
			// The user's second factor holds every login, through an upstream too.
			const [name, part] = secondFactorArea.part({ mode: "optional" });
			const scene: AreaScene = { parts: { ...federation.parts, [name]: part } };
			running = await areaTarget().start(scene);
			if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
			base = running.baseUrl;
		});
		afterAll(async () => {
			if (running?.kind === "running") await running.stop();
			await corp?.stop();
		});

		/**
		 * Binds TOTP to the user from a password session, sending the mailed binding proof where the
		 * target asks one first; answers its secret and the factor's id.
		 */
		async function enrolled() {
			const b = passwordBrowser(() => base);
			expect((await b.login("alice")).status).toBe(200);
			const mail = running.kind === "running" ? running.mail : undefined;
			const begun = await beginBinding(b, { kind: "totp" }, mail);
			const secret = String(begun.body.secret);
			const done = await b.send("POST", "/session/mfa/enrollment/complete", {
				transaction_id: String(begun.body.transaction),
				proof: totp(secret),
			});
			expect(done.status).toBe(200);
			return { secret, factor: (done.body.factor as { id: string }).id };
		}

		/** The access token the receiving client gets by the code flow in the browser's session. */
		async function receiverToken(b: ReturnType<typeof openBrowser>) {
			const asked = new URLSearchParams({
				response_type: "code",
				client_id: receiver.id,
				redirect_uri: callback,
				scope: "openid read",
				state: "s",
				code_challenge: createHash("sha256").update(verifier).digest("base64url"),
				code_challenge_method: "S256",
			});
			const answered = await b.get(`/oauth/authorize?${asked}`);
			const code = new URL(answered.location).searchParams.get("code") ?? "";
			const res = await fetch(`${base}/oauth/token`, {
				method: "POST",
				headers: {
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.41",
					"content-type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					code,
					redirect_uri: callback,
					code_verifier: verifier,
					client_id: receiver.id,
					client_secret: receiver.secret,
				}),
			});
			expect(res.status).toBe(200);
			return ((await res.json()) as { access_token: string }).access_token;
		}

		it("hands the upstream tokens out only once the second factor lets the login through", async () => {
			const { secret, factor } = await enrolled();
			const b = openBrowser(() => base, origin);
			const started = await b.get("/session/oauth/federation/corp");
			const query = corp.authorize(started.location, {
				subject: "u-alice",
				tokens: { accessToken: "up-held" },
			});
			const held = await b.get(`/session/oauth/federation/corp/callback?${query}`);
			expect([held.status, held.body?.error]).toEqual([403, "mfa_required"]);
			// Held, the browser has no session, so no client is issued a token to fetch them with.
			expect(await b.session()).toBe(false);
			const proved = await b.submit("/session/mfa/verify", {
				transaction_id: String(held.body?.transaction),
				factor_id: factor,
				proof: totp(secret, 1),
			});
			expect(proved.status).toBe(200);
			expect(await b.session()).toBe(true);
			const handed = await fetch(`${base}/oauth/federation/corp/token`, {
				method: "POST",
				headers: {
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.41",
					authorization: `Bearer ${await receiverToken(b)}`,
				},
			});
			expect([
				handed.status,
				((await handed.json()) as { access_token: string }).access_token,
			]).toEqual([200, "up-held"]);
		});
	},
);
