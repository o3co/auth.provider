import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
	areaTarget,
	type Fake,
	fakeHttp,
	type Scripted,
	type Started,
	sceneOf,
} from "@mod/conformance";
import { keysArea } from "@mod/conformance-keys";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { httpLedger, identityArea, type LedgerScene, ledgerBesideUsers } from "../src/main.ts";

const issuer = "https://issuer.example";
const credential = randomBytes(32).toString("hex");
const pair = generateKeyPairSync("ed25519");
const keys = keysArea.part({
	signing: {
		kid: "login",
		alg: "EdDSA",
		privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
});
const sceneWith = (ledger: LedgerScene, users: { identifier: string; password: string }[] = []) =>
	sceneOf(keys, identityArea.part({ origin: issuer, users, ledger }));

/** How the fake ledger answers: as a ledger holding alice, or failing in one way. */
type Mode =
	| "alice"
	| "failing"
	| "slow"
	| "refusing"
	| "refusing-403"
	| "not-found"
	| "redirecting"
	| "empty-subject"
	| "malformed";
let mode: Mode = "alice";
const alice = { id: "s-alice", username: "alice", name: "Alice" };
const right = { username: "alice", password: "correct horse battery" };
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A ledger verifying passwords at `/ledger/authenticate`, behind the credential. It refuses an
 * unknown identifier and a wrong password with 401, without a Bearer challenge.
 */
async function asAlice(asked: { method: string; path: string; body: string }): Promise<Scripted> {
	if (asked.method !== "POST" || asked.path !== "/ledger/authenticate") return { status: 404 };
	const { email, password } = JSON.parse(asked.body);
	if (email !== right.username) return { status: 401 };
	return password === right.password ? { json: alice } : { status: 401 };
}

let fake: Fake;
let running: Started;
let base = "";
let sender = 0;
const nextSender = () => `198.51.100.${++sender}`;
const sessionCookie = (cookies: string[]) =>
	cookies
		.map((c) => c.split(";")[0] ?? "")
		.find((c) => /^__Host-[^=]*session=/.test(c) && !/csrf/.test(c));

async function login(form: Record<string, string>) {
	const res = await fetch(`${base}/session/login`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": nextSender(),
			origin: issuer,
			"x-forwarded-host": new URL(issuer).host,
		},
		body: new URLSearchParams(form),
		redirect: "manual",
	});
	return { status: res.status, cookies: res.headers.getSetCookie(), text: await res.text() };
}

describe.runIf(areaTarget().can(httpLedger))("password login: a user ledger over HTTP", () => {
	beforeAll(async () => {
		fake = await fakeHttp(async (asked, at) => {
			if (asked.headers.authorization !== `Bearer ${credential}`) {
				return { status: 401, headers: { "www-authenticate": "Bearer" } };
			}
			switch (mode) {
				case "alice":
					return asAlice(asked);
				case "failing":
					return { status: 500, text: "the ledger failed" };
				case "slow":
					await pause(1500);
					return asAlice(asked);
				case "refusing":
					return { status: 401, headers: { "www-authenticate": 'Bearer error="invalid_token"' } };
				case "refusing-403":
					return {
						status: 403,
						headers: { "www-authenticate": 'Bearer error="insufficient_scope"' },
					};
				case "not-found":
					return { status: 404 };
				case "redirecting":
					return asked.path === "/elsewhere"
						? { json: alice }
						: { status: 302, headers: { location: `${at}/elsewhere` } };
				case "empty-subject":
					return { json: { ...alice, id: "" } };
				case "malformed":
					return { json: { id: "s-alice", username: ["alice"] } };
			}
		});
		running = await areaTarget().start(
			sceneWith({ verifyUrl: `${fake.base}/ledger/authenticate`, credential, timeoutMs: 500 }),
		);
		if (running.kind !== "running") throw new Error(`refused:\n${running.output}`);
		base = running.baseUrl;
	});
	afterAll(async () => {
		if (running?.kind === "running") await running.stop();
		await fake?.stop();
	});

	it("logs in a user the ledger verifies, asking it in the stated shape", async () => {
		mode = "alice";
		const from = fake.received.length;
		const ok = await login(right);
		expect(ok.status).toBe(200);
		expect(sessionCookie(ok.cookies)).toMatch(/^__Host-/);
		const asked = fake.received.slice(from).find((r) => r.path === "/ledger/authenticate");
		expect(asked?.method).toBe("POST");
		expect(asked?.headers).toMatchObject({
			authorization: `Bearer ${credential}`,
			"content-type": "application/json",
		});
		expect(JSON.parse(asked?.body ?? "")).toEqual({
			email: right.username,
			password: right.password,
		});
		expect(fake.received.slice(from).some((r) => r.path.includes(right.password))).toBe(false);
	});

	it("answers a user the ledger does not hold as it answers a wrong password", async () => {
		mode = "alice";
		const wrong = await login({ ...right, password: "nope" });
		const unknown = await login({ ...right, username: "nobody" });
		expect(wrong.status).toBe(401);
		expect([unknown.status, unknown.text]).toEqual([wrong.status, wrong.text]);
		expect(sessionCookie(unknown.cookies)).toBeUndefined();
	});

	it("answers 503 while the ledger fails, is slow, answers 404 or refuses the credential, never as wrong credentials", async () => {
		for (const failing of ["failing", "slow", "not-found", "refusing", "refusing-403"] as const) {
			mode = failing;
			const answer = await login(right);
			expect(answer.status, failing).toBe(503);
			expect(sessionCookie(answer.cookies), failing).toBeUndefined();
		}
	});

	it("answers 503 to a redirect, which it does not follow", async () => {
		mode = "redirecting";
		const from = fake.received.length;
		expect((await login(right)).status).toBe(503);
		expect(fake.received.slice(from).map((r) => r.path)).not.toContain("/elsewhere");
	});

	it("answers 503 to a user with an empty id or a malformed username, opening no session", async () => {
		for (const malformed of ["empty-subject", "malformed"] as const) {
			mode = malformed;
			const answer = await login(right);
			expect(answer.status, malformed).toBe(503);
			expect(sessionCookie(answer.cookies), malformed).toBeUndefined();
		}
	});

	it.runIf(areaTarget().can(ledgerBesideUsers))(
		"refuses to start with users in the settings beside the ledger, never showing the credential",
		async () => {
			const both = await areaTarget().start(
				sceneWith({ verifyUrl: `${fake.base}/ledger/authenticate`, credential }, [
					{ identifier: "bob", password: "bob's password" },
				]),
			);
			if (both.kind === "running") await both.stop();
			expect(both.kind).toBe("refused");
			expect(both.kind === "refused" && both.output).not.toContain(credential);
		},
	);
});
