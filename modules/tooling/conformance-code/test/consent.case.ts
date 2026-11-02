import { createHash, generateKeyPairSync } from "node:crypto";
import { areaTarget, auditEvents, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { codeScene } from "../src/main.ts";
import { browserAt } from "../src/testing.ts";

const issuer = "https://issuer.example";
const callback = "https://third.example/cb";
const pair = generateKeyPairSync("ed25519");
const challenge = createHash("sha256").update("v".repeat(43)).digest("base64url");
const password = "correct horse battery";
const users = [
	{ identifier: "alice", password },
	{ identifier: "bob", password },
	{ identifier: "carol", password },
];
const scene = codeScene({
	issuer,
	keys: {
		signing: {
			kid: "cs",
			alg: "EdDSA",
			privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
			publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
		},
	},
	clients: [
		{
			id: "third",
			kind: "confidential",
			method: "client_secret_post",
			secret: "third-secret-0123456789abcdef",
			grants: ["authorization_code"],
			scopes: ["openid", "read"],
			redirectUris: [callback],
		},
	],
	users,
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

const request = {
	response_type: "code",
	client_id: "third",
	redirect_uri: callback,
	state: "s1",
	scope: "openid",
	code_challenge: challenge,
	code_challenge_method: "S256",
};
const bodies = {
	form: (fields: Record<string, string>) => ({
		type: "application/x-www-form-urlencoded",
		body: new URLSearchParams(fields).toString(),
	}),
	json: (fields: Record<string, string>) => ({
		type: "application/json",
		body: JSON.stringify(fields),
	}),
};

/** One user answering the consent page with one kind of body, following each redirect on the issuer. */
function answering(username: string, kind: keyof typeof bodies) {
	const browser = browserAt(() => base, issuer, { username, password });
	const follow = async (location: string): Promise<URL> => {
		const at = new URL(location, issuer);
		if (at.origin !== issuer) return at;
		const res = await fetch(`${base}${at.pathname}${at.search}`, {
			redirect: "manual",
			headers: browser.headers({ cookie: await browser.login() }),
		});
		return follow(res.headers.get("location") ?? "");
	};
	return async (decision: "accept" | "deny") => {
		const asked = await browser.authorize(request);
		const page = asked.at;
		expect(`${page?.origin}${page?.pathname}`).toBe(`${issuer}/consent`);
		const { type, body } = bodies[kind]({
			challenge: page?.searchParams.get("challenge") ?? "",
			decision,
		});
		const res = await fetch(`${base}/oauth/consent`, {
			method: "POST",
			redirect: "manual",
			headers: browser.headers({
				cookie: await browser.login(),
				origin: issuer,
				"content-type": type,
			}),
			body,
		});
		expect(res.status).toBe(303);
		const back = await follow(res.headers.get("location") ?? "");
		return {
			at: `${back.origin}${back.pathname}`,
			state: back.searchParams.get("state"),
			error: back.searchParams.get("error"),
			code: back.searchParams.has("code"),
			// Accepted once, the next request goes straight back to the client.
			again: (await browser.authorize(request)).at?.searchParams.has("code") ?? false,
		};
	};
}

describe("consent: the page's answer", () => {
	it("is taken as a JSON body as it is as a form, for a refusal and an acceptance [oidc-core-3.1.2.4-a] [oidc-core-3.1.2.6-c] [oidc-core-3.1.2.6-d] [rfc6749-4.1.2-a] [rfc6749-4.1.2-f] [rfc6749-4.1.2.1-c] [rfc6749-4.1.2.1-g]", async () => {
		const outcomes = async (answer: ReturnType<typeof answering>) => [
			await answer("deny"),
			await answer("accept"),
		];
		const byForm = await outcomes(answering("alice", "form"));
		const byJson = await outcomes(answering("bob", "json"));
		expect(byForm).toEqual([
			{ at: callback, state: "s1", error: "access_denied", code: false, again: false },
			{ at: callback, state: "s1", error: null, code: true, again: true },
		]);
		expect(byJson).toEqual(byForm);
	});
});

describe.runIf(areaTarget().can(auditEvents.need))("consent: audit events", () => {
	it("records a refusal and an acceptance with the subject, the client and the range", async () => {
		const answer = answering("carol", "form");
		const trail = auditEvents.of(running);
		const denied = await trail.during(() => answer("deny"));
		const accepted = await trail.during(() => answer("accept"));
		const decided = (events: readonly { kind: string }[]) =>
			events.filter((event) => event.kind.startsWith("consent."));
		const recorded = (kind: string) => ({
			kind,
			at: expect.any(Number),
			subject: expect.stringMatching(/./),
			attributes: { client: "third", source: expect.any(String), scopes: "openid" },
		});
		expect(decided(denied.events)).toEqual([recorded("consent.denied")]);
		expect(decided(accepted.events)).toEqual([recorded("consent.granted")]);
		expect(JSON.stringify([denied.events, accepted.events])).not.toContain(password);
	});
});
