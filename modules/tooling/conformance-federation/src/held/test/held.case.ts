import { createHash, generateKeyPairSync } from "node:crypto";
import { type AreaScene, areaTarget, type Started } from "@mod/conformance";
import { secondFactorArea } from "@mod/conformance-second-factor";
import { totp } from "@mod/conformance-second-factor/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Browser, browser as openBrowser, probeClient } from "../../../test/browser.ts";
import { fakeUpstream } from "../../../test/upstream.ts";
import { federationScene } from "../../main.ts";

const origin = "https://issuer.example";
const heldPage = `${origin}/login/held`;
const landing = "https://app.example/home";
const asked = "https://app.example/reports";
const callback = "https://app.example/cb";
const verifier = "h".repeat(43);
const password = "correct horse battery";
const pair = generateKeyPairSync("ed25519");
const upstreamClient = { id: "as-client", secret: "as-client-secret-0123456789" };
const receiver = { id: "fed-app", secret: "fed-app-secret-0123456789abcdef" };
const users = ["alice", "bob", "carol"];

/** A deployment whose second factor every login needs, through an upstream too. */
function deployed(options: { readonly heldPage?: string; readonly landing?: string }) {
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
			...options,
			returnTargets: [asked],
			users: users.map((name) => ({
				identifier: name,
				password,
				upstream: { idp: "corp", subject: `u-${name}` },
			})),
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
		const [name, part] = secondFactorArea.part({ mode: "required" });
		const scene: AreaScene = { parts: { ...federation.parts, [name]: part } };
		running = await areaTarget().start(scene);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
		await corp?.stop();
	});

	/** A browser's login through the upstream as `user`, asking `to` as its return target. */
	async function upstreamLogin(user: string, to?: string) {
		const b = openBrowser(() => base, origin);
		const target = to === undefined ? "" : `?${new URLSearchParams({ redirect_to: to })}`;
		const started = await b.get(`/session/oauth/federation/corp${target}`);
		const query = corp.authorize(started.location, {
			subject: `u-${user}`,
			tokens: { accessToken: `up-${user}` },
		});
		return { b, answer: await b.get(`/session/oauth/federation/corp/callback?${query}`) };
	}

	/** Binds TOTP in the held login, sending the mailed binding proof where the target asks one. */
	async function bind(b: Browser, transaction: string) {
		const mail = running.kind === "running" ? running.mail : undefined;
		const before = mail?.received.length ?? 0;
		const form = { kind: "totp", transaction_id: transaction };
		let begun = await b.submit("/session/mfa/enrollment", form);
		const proved = begun.body?.error === "mfa_binding_proof_required" && mail !== undefined;
		if (proved) {
			const code = /\b([0-9A-Z]{16})\b/.exec(mail.received.slice(before).at(-1)?.text ?? "")?.[1];
			begun = await b.submit("/session/mfa/enrollment", {
				...form,
				transaction_id: String(begun.body?.transaction),
				proof: code ?? "",
			});
		}
		const secret = String(begun.body?.secret);
		const done = await b.submit("/session/mfa/enrollment/complete", {
			transaction_id: transaction,
			proof: totp(secret),
		});
		expect(done.status).toBe(200);
		return { secret, proved };
	}

	/** The user's TOTP secret, bound in a first upstream login the factor holds. */
	async function enrolled(user: string) {
		const { b } = await upstreamLogin(user);
		return (await bind(b, (await read(b)).transaction)).secret;
	}

	/** The access token the receiving client gets by the code flow in the browser's session. */
	async function receiverToken(b: Browser) {
		const code_challenge = createHash("sha256").update(verifier).digest("base64url");
		const authorize = new URLSearchParams({
			response_type: "code",
			client_id: receiver.id,
			redirect_uri: callback,
			scope: "openid read",
			state: "s",
			code_challenge,
			code_challenge_method: "S256",
		});
		const answered = await b.get(`/oauth/authorize?${authorize}`);
		const res = await fetch(`${base}/oauth/token`, {
			method: "POST",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.41",
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code: new URL(answered.location).searchParams.get("code") ?? "",
				redirect_uri: callback,
				code_verifier: verifier,
				client_id: receiver.id,
				client_secret: receiver.secret,
			}),
		});
		expect(res.status).toBe(200);
		return ((await res.json()) as { access_token: string }).access_token;
	}

	/** The upstream access token handed to the receiving client in the browser's session. */
	async function handed(b: Browser) {
		const res = await fetch(`${base}/oauth/federation/corp/token`, {
			method: "POST",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.41",
				authorization: `Bearer ${await receiverToken(b)}`,
			},
		});
		return [res.status, ((await res.json()) as { access_token?: string }).access_token];
	}

	return { upstreamLogin, bind, enrolled, handed };
}

/** What the held page reads of the login, by the browser's cookies alone. */
async function read(b: Browser) {
	const answer = await b.get("/session/mfa/transaction");
	expect(answer.status).toBe(200);
	const factors = answer.body?.factors as { id: string; kind: string }[];
	return {
		transaction: String(answer.body?.transaction),
		purpose: answer.body?.purpose,
		totp: factors.find((f) => f.kind === "totp")?.id ?? "",
	};
}

/** The page proving the login's TOTP factor with the code one step ahead. */
const verify = (b: Browser, login: Awaited<ReturnType<typeof read>>, secret: string) =>
	b.submit("/session/mfa/verify", {
		transaction_id: login.transaction,
		factor_id: login.totp,
		proof: totp(secret, 1),
	});

// Ours holds a federation login at the login gates, as any other login.
describe.runIf(!areaTarget().differs("federation-login-held-at-gates"))(
	"federation: a login a gate holds",
	() => {
		describe("with a held page", () => {
			const d = deployed({ heldPage, landing });

			it("sends a login held for a first binding to the held page, by 303 with no query, where it binds a factor", async () => {
				const { b, answer } = await d.upstreamLogin("bob");
				expect([answer.status, answer.location, answer.text]).toEqual([303, heldPage, ""]);
				expect(await b.session()).toBe(false);
				const login = await read(b);
				expect(login.purpose).toBe("enroll-login");
				const { proved } = await d.bind(b, login.transaction);
				// Bound with no binding proof, the factor counts from the next login; after one, it lets this one in.
				expect(await b.session()).toBe(proved);
			});

			it("goes on at the held page: the factor proved there lets the login in where it asked, and hands the upstream tokens", async () => {
				const secret = await d.enrolled("alice");
				const { b, answer } = await d.upstreamLogin("alice", asked);
				expect([answer.status, answer.location]).toEqual([303, heldPage]);
				// Held, the browser has no session, so no client is issued a token to fetch them with.
				expect(await b.session()).toBe(false);
				const login = await read(b);
				expect(login.purpose).toBe("login");
				const proved = await verify(b, login, secret);
				expect([proved.status, proved.body?.redirect_to]).toEqual([200, asked]);
				expect(await b.session()).toBe(true);
				expect(await d.handed(b)).toEqual([200, "up-alice"]);
			});

			it("lands a held login that asked no target at the landing", async () => {
				const secret = await d.enrolled("carol");
				const { b } = await d.upstreamLogin("carol");
				const proved = await verify(b, await read(b), secret);
				expect([proved.status, proved.body?.redirect_to]).toEqual([200, landing]);
			});
		});

		describe("without a held page", () => {
			const d = deployed({});

			it("answers a held login 403 with the gate's answer; proved, it lands at the origin's root", async () => {
				const secret = await d.enrolled("alice");
				const { b, answer } = await d.upstreamLogin("alice");
				expect([answer.status, answer.body?.error]).toEqual([403, "mfa_required"]);
				const login = await read(b);
				expect(login.transaction).toBe(String(answer.body?.transaction));
				const proved = await verify(b, login, secret);
				expect([proved.status, proved.body?.redirect_to]).toEqual([200, `${origin}/`]);
			});
		});
	},
);
