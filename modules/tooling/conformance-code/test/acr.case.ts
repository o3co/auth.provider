import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import type { ClientScene } from "@mod/conformance-oauth";
import { stepUpPage } from "@mod/conformance-second-factor";
import {
	browser,
	issuer,
	letInByRecovery,
	password,
	running,
	secondFactorAcr,
	stepUp,
} from "@mod/conformance-second-factor/testing";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type CodeScene, codeScene } from "../src/main.ts";
import { backChannel, browserAt, succeeded } from "../src/testing.ts";

const callback = "https://app.example/cb";
const pair = generateKeyPairSync("ed25519");
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
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
const sceneWith = (extra: Partial<CodeScene>, users: string[]) =>
	codeScene({
		issuer,
		keys: {
			signing: {
				kid: "acr",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		clients: [app],
		users: users.map((identifier) => ({ identifier, password })),
		...extra,
	});
const request = (extra: Record<string, string> = {}) => ({
	response_type: "code",
	client_id: "app",
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
	...extra,
});
/** The claims of the ID token a code brings. */
const claimsOf = async (base: string, code: string) => {
	const res = await fetch(`${base}/oauth/token`, {
		method: "POST",
		headers: { ...backChannel, "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: "app",
			client_secret: app.secret ?? "",
			code,
			redirect_uri: callback,
			code_verifier: verifier,
		}),
	});
	const token = String((await succeeded(res, "the token endpoint")).id_token ?? "");
	return JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString()) as {
		acr?: string;
	};
};

describe("acr: a table without second factors", () => {
	const scene = sceneWith(
		{ acr: { values: { "urn:t:pwd": [["pwd"]], "urn:t:any": [["pwd"], ["hwk"]] } } },
		["alice"],
	);
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
	const b = browserAt(() => base, issuer, { username: "alice", password });

	it("answers unmet when no acr asked is in the table, and passes over the unknown ones", async () => {
		const unknown = await b.authorize(request({ acr_values: "urn:t:none" }));
		expect(unknown.at?.searchParams.get("error")).toBe("unmet_authentication_requirements");
		const mixed = await b.authorize(request({ acr_values: "urn:t:none urn:t:pwd" }));
		const code = mixed.at?.searchParams.get("code") ?? "";
		expect((await claimsOf(base, code)).acr).toBe("urn:t:pwd");
	});

	it("puts in the ID token the first acr met in the order asked, and none when none was asked", async () => {
		for (const [asked, met] of [
			["urn:t:any urn:t:pwd", "urn:t:any"],
			["urn:t:pwd urn:t:any", "urn:t:pwd"],
		] as const) {
			const res = await b.authorize(request({ acr_values: asked }));
			expect((await claimsOf(base, res.at?.searchParams.get("code") ?? "")).acr).toBe(met);
		}
		const plain = await b.authorize(request());
		expect((await claimsOf(base, plain.at?.searchParams.get("code") ?? "")).acr).toBeUndefined();
	});

	it("refuses a claims parameter that asks for acr or is no object, and ignores other claims", async () => {
		const asked = JSON.stringify({ id_token: { acr: { essential: true, values: ["urn:t:pwd"] } } });
		for (const claims of [asked, JSON.stringify({ userinfo: { acr: null } }), "not json"]) {
			const res = await b.authorize(request({ claims }));
			expect(res.at?.searchParams.get("error")).toBe("invalid_request");
		}
		const other = await b.authorize(
			request({ claims: JSON.stringify({ id_token: { email: null } }) }),
		);
		expect(other.at?.searchParams.has("code")).toBe(true);
	});
});

describe("acr: raising a session with a second factor", () => {
	const s = running(
		sceneWith({ mfa: { mode: "optional" }, acr: { values: { "urn:t:otp": [["pwd", "otp"]] } } }, [
			"bob",
			"cara",
		]),
	);
	/** Asks for a code from a browser that keeps its own cookies. */
	const ask = async (b: ReturnType<typeof browser>, query: Record<string, string> | string) => {
		const text = typeof query === "string" ? query : new URLSearchParams(query).toString();
		const res = await fetch(`${s.at.base}/oauth/authorize?${text}`, {
			redirect: "manual",
			headers: {
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.30",
				"x-forwarded-host": new URL(issuer).host,
				cookie: [...b.jar].map(([k, v]) => `${k}=${v}`).join("; "),
			},
		});
		const location = res.headers.get("location") ?? "";
		return location ? new URL(location, issuer) : undefined;
	};

	it("answers interaction_required without asking, sends a short session once to raise it, and offers the second-factor acr [oidc-core-3.1.2.1-k] [oidc-core-3.1.2.3-c] [oidc-core-3.1.2.3-d]", async () => {
		const b = browser(() => s.at.base);
		expect((await b.login("bob")).status).toBe(200);
		const quiet = await ask(b, request({ acr_values: "urn:t:otp", prompt: "none" }));
		expect(quiet?.searchParams.get("error")).toBe("interaction_required");
		const sent = await ask(b, request({ acr_values: "urn:t:none urn:t:otp" }));
		expect(sent?.pathname).toBe(stepUpPage);
		expect(sent?.searchParams.get("acr_values")).toBe("urn:t:otp");
		const back = new URL(sent?.searchParams.get("redirect_to") ?? "", issuer);
		expect(back.pathname).toBe("/oauth/authorize");
		const unraised = await ask(b, back.search.slice(1));
		expect(unraised?.searchParams.get("error")).toBe("unmet_authentication_requirements");
		const offered = await ask(b, request({ acr_values: secondFactorAcr }));
		expect(offered?.pathname).toBe(stepUpPage);
	});

	it("issues a code with the acr once the session is raised by a step-up", async () => {
		const { secret, codes } = await s.enrol("cara");
		const { b, transaction } = await s.held("cara");
		await letInByRecovery(b, transaction, codes[0] ?? "");
		const sent = await ask(b, request({ acr_values: "urn:t:otp" }));
		expect(sent?.pathname).toBe(stepUpPage);
		const raised = await stepUp(b, secret);
		expect(raised.status).toBe(200);
		const back = new URL(sent?.searchParams.get("redirect_to") ?? "", issuer);
		const done = await ask(b, back.search.slice(1));
		const code = done?.searchParams.get("code") ?? "";
		expect((await claimsOf(s.at.base, code)).acr).toBe("urn:t:otp");
	});
});

describe("acr: an acr no way of logging in can meet", () => {
	it("refuses to start, or, on a target that differs, answers it as unknown", async () => {
		// About a deployment where nothing gives otp.
		const scene = sceneWith(
			{ acr: { values: { "urn:t:otp": [["otp"]] } }, without: ["@mod/mfa-totp"] },
			["dan"],
		);
		const started = await areaTarget().start(scene);
		try {
			if (!areaTarget().differs("unmeetable-acr-entry")) {
				expect(started.kind).toBe("refused");
				return;
			}
			if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
			const b = browserAt(() => started.baseUrl, issuer, { username: "dan", password });
			const res = await b.authorize(request({ acr_values: "urn:t:otp" }));
			expect(res.at?.searchParams.get("error")).toBe("unmet_authentication_requirements");
		} finally {
			if (started.kind === "running") await started.stop();
		}
	});
});
