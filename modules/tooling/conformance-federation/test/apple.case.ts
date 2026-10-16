import { generateKeyPairSync } from "node:crypto";
import { areaTarget, type Started } from "@mod/conformance";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { federationScene, type IdpScene } from "../src/main.ts";
import { type AppleAuthorized, fakeApple } from "./apple.ts";
import { type Browser, browser as openBrowser, probeClient } from "./browser.ts";

const origin = "https://issuer.example";
const landing = "https://app.example/home";
const appleSite = "https://appleid.apple.com";
const pair = generateKeyPairSync("ed25519");
const team = generateKeyPairSync("ec", { namedCurve: "P-256" });
const signing = {
	teamId: "TEAM123456",
	keyId: "KEY1234567",
	privateKey: team.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
};
const client = {
	id: "com.example.web",
	secret: "apple-fixed-secret-0123456789",
	team: { id: signing.teamId, publicKey: team.publicKey },
};

let apple: Awaited<ReturnType<typeof fakeApple>>;
let running: Started;
let base = "";

/** The scene: Apple with a fixed secret, and Apple with one its team signs, and anything a scene changes. */
const sceneWith = (idps: readonly IdpScene[], at = origin) =>
	federationScene({
		origin: at,
		keys: {
			signing: {
				kid: "a",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		},
		idps,
		landing,
		returnTargets: [],
		users: [
			{
				identifier: "alice",
				password: "correct horse battery",
				upstream: { idp: "apple", subject: "000123.alice" },
			},
			{
				identifier: "bob",
				password: "correct horse battery",
				upstream: { idp: "apple-signed", subject: "000456.bob" },
			},
		],
		clients: [probeClient],
	});
const fixed = (): IdpScene => ({
	name: "apple",
	type: "apple",
	issuer: apple.base,
	clientId: client.id,
	clientSecret: client.secret,
});
const signed = (): IdpScene => ({
	name: "apple-signed",
	type: "apple",
	issuer: apple.base,
	clientId: client.id,
	signing,
});

beforeAll(async () => {
	apple = await fakeApple(client);
	running = await areaTarget().start(sceneWith([fixed(), signed()]));
	if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
	base = running.baseUrl;
});
afterAll(async () => {
	if (running?.kind === "running") await running.stop();
	await apple?.stop();
});

const browser = () => openBrowser(() => base, origin);
const startOf = (idp: string) => `/session/oauth/federation/${idp}`;
/** Starts a login, checks what Apple is asked, and authorizes it there; answers the posted form. */
async function authorized(b: Browser, as: AppleAuthorized, idp = "apple", query = "") {
	const started = await b.get(`${startOf(idp)}${query}`);
	expect(started.status).toBe(302);
	// Checked by path alone: the host is the target's to choose.
	const asked = new URL(started.location);
	expect(asked.pathname).toBe("/auth/authorize");
	expect(asked.searchParams.get("redirect_uri")).toBe(`${origin}${startOf(idp)}/callback`);
	return { form: apple.authorize(started.location, as), asked: asked.searchParams };
}
const posted = (b: Browser, form: URLSearchParams, idp = "apple", kept?: string) =>
	b.post(`${startOf(idp)}/callback`, form, appleSite, kept);

describe("federation through Apple", () => {
	it("logs a browser in by the answer Apple posts, paying with the fixed secret", async () => {
		const b = browser();
		const { form, asked } = await authorized(b, { subject: "000123.alice" });
		expect(asked.get("response_mode")).toBe("form_post");
		expect(asked.get("nonce")).toMatch(/./);
		const back = await posted(b, form);
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
		expect(apple.secrets.at(-1)).toBe("fixed");
	});

	it("logs a browser in paying with a secret the team's key signs", async () => {
		const b = browser();
		const { form } = await authorized(b, { subject: "000456.bob" }, "apple-signed");
		const back = await posted(b, form, "apple-signed");
		expect([back.status, back.location]).toEqual([302, landing]);
		expect(await b.session()).toBe(true);
		expect(apple.secrets.at(-1)).toBe("signed");
	});

	it("answers its callback by GET with 405, and a post with no answer, spending neither", async () => {
		const b = browser();
		const { form } = await authorized(b, { subject: "000123.alice" });
		const got = await b.get(`${startOf("apple")}/callback?${form}`);
		expect([got.status, got.headers.get("allow")]).toEqual([405, "POST"]);
		// What another site posts carries no answer: no state, no code.
		const empty = await posted(b, new URLSearchParams());
		expect(empty.status).toBe(400);
		expect((await posted(b, form)).status).toBe(302);
	});

	it("refuses an answer naming another issuer before its code is used", async () => {
		const b = browser();
		const { form } = await authorized(b, { subject: "000123.alice" });
		form.set("iss", "https://evil.example");
		expect((await posted(b, form)).status).toBe(502);
		expect(apple.tokenCalls).not.toContain(form.get("code"));
		expect(await b.session()).toBe(false);
	});

	it("refuses an id_token Apple did not sign, and one for another login", async () => {
		const cases: Record<string, AppleAuthorized> = {
			forged: { subject: "000123.alice", forged: true },
			"another nonce": { subject: "000123.alice", nonce: "not-this-login" },
		};
		for (const [named, as] of Object.entries(cases)) {
			const b = browser();
			const { form } = await authorized(b, as);
			expect((await posted(b, form)).status, named).toBe(502);
			expect(await b.session()).toBe(false);
		}
	});

	it("logs in the same whatever the posted user field holds", async () => {
		const long = "x".repeat(4000);
		for (const user of [
			JSON.stringify({ name: { firstName: long, lastName: long } }),
			"{not json",
		]) {
			const b = browser();
			const { form } = await authorized(b, { subject: "000123.alice", user });
			expect((await posted(b, form)).status).toBe(302);
			expect(await b.session()).toBe(true);
		}
	});
});

describe.skipIf(areaTarget().differs("apple-freshness-login-required"))(
	"federation through Apple: freshness",
	() => {
		it("cannot pass a request to log in again on to Apple, so refuses it as login_required", async () => {
			const b = browser();
			const { form, asked } = await authorized(
				b,
				{ subject: "000123.alice" },
				"apple",
				"?prompt=login",
			);
			expect([asked.get("prompt"), asked.get("max_age")]).toEqual([null, null]);
			const back = await posted(b, form);
			expect([back.status, back.body?.error]).toEqual([401, "login_required"]);
			expect(await b.session()).toBe(false);
		});
	},
);

describe("federation through Apple: its key set", () => {
	it("logs in with an id_token under a key Apple has moved to", { timeout: 120_000 }, async () => {
		await apple.rotate();
		// A key set is fetched again for a key it lacks, but not within a minute of its last fetch.
		await new Promise((done) => setTimeout(done, 61_000));
		const b = browser();
		const { form } = await authorized(b, { subject: "000123.alice" });
		expect((await posted(b, form)).status).toBe(302);
		expect(await b.session()).toBe(true);
	});
});

describe("federation through Apple: boot", () => {
	const refused = async (idps: readonly IdpScene[], at = origin) => {
		const started = await areaTarget().start(sceneWith(idps, at));
		if (started.kind === "running") await started.stop();
		return started.kind;
	};

	it("starts with Apple alone, as the refusals below change one thing of it", async () => {
		expect(await refused([fixed()])).toBe("running");
	});

	it("refuses a callback Apple would refuse: on plain http, or on loopback", async () => {
		expect(await refused([fixed()], "http://issuer.example")).toBe("refused");
		expect(await refused([fixed()], "https://localhost")).toBe("refused");
	});

	it("refuses both a fixed and a signed secret, neither, and part of what signs one", async () => {
		const { clientSecret: _, ...none } = fixed();
		expect(await refused([{ ...fixed(), signing }])).toBe("refused");
		expect(await refused([none])).toBe("refused");
		const { privateKey: __, ...part } = signing;
		expect(await refused([{ ...signed(), signing: part }])).toBe("refused");
	});
});
