import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import {
	browser as heldBrowser,
	letInByRecovery,
	running as runningWith,
} from "@mod/conformance-second-factor/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../../main.ts";
import { browserAt } from "../../testing.ts";

const issuer = "https://issuer.example";
const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const challenge = createHash("sha256").update("v".repeat(43)).digest("base64url");
const app: ClientScene = {
	id: "app",
	kind: "confidential",
	method: "client_secret_post",
	secret: "app-secret-0123456789abcdef",
	grants: ["authorization_code"],
	scopes: ["openid"],
	defaultScopes: ["openid"],
	redirectUris: [callback],
	firstParty: true,
};
const parts: CodeScene = {
	issuer,
	keys: {
		signing: {
			kid: "fresh",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [app],
	users: [{ identifier: "alice", password: "correct horse battery" }],
};
const scene = codeScene(parts);

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

const browser = browserAt(() => base, issuer, {
	username: "alice",
	password: "correct horse battery",
});
const request = (extra: Record<string, string>) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});

/** The request the deployment sends the browser back to once it logs in; what follows `?`. */
async function sentToLogIn(extra: Record<string, string>) {
	const res = await browser.authorize(request(extra));
	expect(res.status).toBe(302);
	const back = new URL(res.at?.searchParams.get("redirect_to") ?? "", issuer);
	expect(`${back.origin}${back.pathname}`).toBe(`${issuer}/oauth/authorize`);
	return back;
}
const errorOf = async (back: URL) =>
	(await browser.authorize(back.search.slice(1))).at?.searchParams.get("error");
const codeOf = async (back: URL) =>
	(await browser.authorize(back.search.slice(1))).at?.searchParams.has("code");
/** A new password login, as the login page makes one, for the next request. */
const logInAgain = async () => {
	browser.forget();
	await browser.login();
};

describe("password logins meeting a client's demand for a fresh login", () => {
	it("meets prompt=login only with a login after the demand, refusing a return without one [oidc-core-3.1.2.1-l] [oidc-core-3.1.2.1-m] [oidc-core-3.1.2.3-a] [oidc-core-3.1.2.3-b] [guarantee-2-a] [oidc-core-15.1-b]", async () => {
		await browser.login();
		const stale = await sentToLogIn({ prompt: "login" });
		expect(await errorOf(stale)).toBe("login_required");
		const back = await sentToLogIn({ prompt: "login" });
		await logInAgain();
		expect(await codeOf(back)).toBe(true);
	});

	// The legacy build counts a login in the same second as within max_age=0, and asks no new one.
	it.skipIf(areaTarget().differs("max-age-zero-asks-a-new-login"))(
		"meets max_age=0 only with a login after the demand, refusing a return without one [oidc-core-3.1.2.1-r] [oidc-core-15.1-f] [guarantee-2-b]",
		async () => {
			await browser.login();
			const stale = await sentToLogIn({ max_age: "0" });
			expect(await errorOf(stale)).toBe("login_required");
			const back = await sentToLogIn({ max_age: "0" });
			await logInAgain();
			expect(await codeOf(back)).toBe(true);
		},
	);

	// The legacy build keeps no record of the demand, so a return without it is a request like any other.
	it.skipIf(areaTarget().differs("return-keeps-its-demand"))(
		"refuses a return whose demand was taken out of it, its re-authentication kept [guarantee-2-a]",
		async () => {
			await browser.login();
			const back = await sentToLogIn({ prompt: "login" });
			back.searchParams.delete("prompt");
			await logInAgain();
			expect(await errorOf(back)).toBe("login_required");
		},
	);
});

describe("a password login a second factor holds for longer than max_age", () => {
	const s = runningWith(
		codeScene({
			...parts,
			mfa: { mode: "optional" },
			users: [{ identifier: "dana", password: "correct horse battery" }],
		}),
	);
	/** Asks for a code from a browser that keeps its own cookies; answers where it is sent. */
	const ask = async (b: ReturnType<typeof heldBrowser>, query: string) => {
		const res = await fetch(`${s.at.base}/oauth/authorize?${query}`, {
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.30",
				"x-forwarded-host": new URL(issuer).host,
				cookie: [...b.jar].map(([k, v]) => `${k}=${v}`).join("; "),
			},
		});
		return new URL(res.headers.get("location") ?? "", issuer);
	};

	// The legacy build counts max_age from the password, so it refuses a second factor slower than it.
	it.skipIf(areaTarget().differs("max-age-from-the-second-factor"))(
		"counts max_age from when the second factor lets the login in, not from the password [guarantee-2-b]",
		async () => {
			const { codes } = await s.enrol("dana");
			const b = heldBrowser(() => s.at.base);
			const sent = await ask(b, new URLSearchParams(request({ max_age: "3" })).toString());
			const back = sent.searchParams.get("redirect_to") ?? "";
			// The page logs in, then the browser follows the return, as the other scenes here do.
			const login = await b.login("dana");
			expect(login.status).toBe(403);
			// The second factor takes longer than max_age allows after the password; max_age leaves a slow
			// runner seconds, not one, between the second factor and the next request.
			await new Promise((resolve) => setTimeout(resolve, 3500));
			const done = await letInByRecovery(b, String(login.body.transaction), codes[0] ?? "");
			expect(done.status).toBe(200);
			const answered = await ask(b, new URL(back, issuer).search.slice(1));
			expect(answered.searchParams.has("code")).toBe(true);
		},
	);
});
