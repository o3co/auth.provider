import { auditStandIn } from "@mod/audit/testing";
import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type RegistrationRefusal, type Registrations, registrations } from "@mod/passkeys";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { entryRequirements } from "@mod/session-requirements";
import sessionRequirements from "@mod/session-requirements/module";
import { subjectRevocation } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import registration from "../src/module.ts";

const origin = "https://rp.example";
const runtime = quietRuntime();
let stop = async () => {};
afterEach(() => stop());

/** Subjects named `held-*` are short of what changing credentials asks. */
const holding = defineModule({ name: "holding" }, (m) => [
	m.contribute(entryRequirements).by(() => ({
		name: "holding",
		judges: ["credentials"],
		admits: async (context, level) =>
			level === "credentials" && context.subject.startsWith("held-")
				? { kind: "short" as const, answer: { error: "step_up_required" } }
				: { kind: "admit" as const },
	})),
]);

type Registered = Awaited<ReturnType<Registrations["register"]>>;
const credential = {
	id: "Y3JlZA",
	publicKey: "a2V5",
	signCount: 0,
	userHandle: "aGFuZGxl",
	backupEligible: true,
	backedUp: true,
	transports: ["internal", "hybrid"],
};

/** The routes over a `registrations` that answers `state`, and records what it was asked. */
async function serve(section: Record<string, unknown> = {}) {
	const state = {
		answer: { kind: "registered", credential, challengedAt: Date.now() } as Registered,
		down: false,
		/** Revokes the subject as its registration is written, as a reset racing it would. */
		revokeWhileWriting: false,
		listed: [] as unknown[],
		renamed: "renamed" as "renamed" | "unknown",
		removed: { removed: true, empty: false },
	};
	let revoke = async (_subject: string) => {};
	const asked: unknown[][] = [];
	const audit = auditStandIn();
	const standIn = defineModule({ name: "passkeys" }, (m) => [
		m.provide(registrations).by(() => ({
			creation: async (subject) => {
				asked.push(["creation", subject]);
				if (state.down) throw new Unavailable("passkeys");
				return { options: { for: subject } };
			},
			register: async (...args) => {
				asked.push(["register", ...args]);
				if (state.down) throw new Unavailable("passkeys");
				// As passkeys does: the caller's check, asked once the record is written.
				if (state.revokeWhileWriting) await revoke(args[0]);
				const admitted = args[3];
				const answer = state.answer;
				if (
					answer.kind === "registered" &&
					admitted &&
					!(await admitted(answer.challengedAt ?? 0))
				) {
					return { kind: "refused", reason: "revoked" } as const;
				}
				return answer;
			},
			listed: async (subject) => {
				asked.push(["listed", subject]);
				if (state.down) throw new Unavailable("passkeys");
				return state.listed as never;
			},
			renamed: async (...args) => {
				asked.push(["renamed", ...args]);
				return state.renamed;
			},
			removed: async (...args) => {
				asked.push(["removed", ...args]);
				return state.removed;
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			csrfStandIn,
			cookiesModule,
			sessionStandIn,
			sessionRequirements,
			subjectRevocationStandIn,
			rateLimitStandIn,
			holding,
			standIn,
			audit.module,
			registration,
		],
		config: {
			...kernelConfig(),
			...httpConfig({ "public-origin": origin, "trusted-proxies": ["127.0.0.1"] }),
			"passkey-registration": section,
		},
		runtime,
	});
	await app.start();
	stop = () => app.stop(1000);
	revoke = (subject) => app.get(subjectRevocation).revoke(subject);
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** A browser signed in as `subject`, or none, posting from `from`. */
	const browser = async (subject?: string, from = origin) => {
		const done = subject
			? await app
					.get(sessions)
					.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() })
			: undefined;
		const cookie = (done?.cookies ?? []).map((c) => c.split(";")[0]).join("; ");
		return async (path: string, body?: unknown, type = "application/json", method = "POST") => {
			const url = path.startsWith("/") ? path : `/oauth/webauthn/registration/${path}`;
			const res = await fetch(`${base}${url}`, {
				method,
				headers: {
					origin: from,
					"x-forwarded-proto": "https",
					"x-forwarded-for": "198.51.100.1",
					cookie,
					...(body === undefined ? {} : { "content-type": type }),
				},
				...(body === undefined
					? {}
					: { body: typeof body === "string" ? body : JSON.stringify(body) }),
			});
			const text = await res.text();
			return {
				status: res.status,
				body: (text ? JSON.parse(text) : undefined) as Record<string, unknown>,
				cacheControl: res.headers.get("cache-control"),
				...(res.headers.has("retry-after") ? { retryAfter: res.headers.get("retry-after") } : {}),
			};
		};
	};
	return { state, asked, browser, events: audit.events };
}

describe("registration from a session", () => {
	it("answers webauthn's options for the session's subject, not cacheable", async () => {
		const { browser, asked } = await serve();
		const post = await browser("sam");
		expect(await post("options")).toEqual({
			status: 200,
			body: { for: "sam" },
			cacheControl: "no-store",
		});
		expect(asked).toEqual([["creation", "sam"]]);
	});

	it("keeps the response for the session's subject with its nickname, answering the credential's id, transports and backup state", async () => {
		const { browser, asked, state, events } = await serve();
		const post = await browser("sam");
		const response = { id: "Y3JlZA", subject: "kim" };
		expect(await post("verify", { response, nickname: "laptop", subject: "kim" })).toMatchObject({
			status: 200,
			body: { credentialId: "Y3JlZA", transports: ["internal", "hybrid"], backedUp: true },
			cacheControl: "no-store",
		});
		expect(asked).toEqual([["register", "sam", response, "laptop", expect.any(Function)]]);
		const { transports: _, ...bare } = credential;
		state.answer = {
			kind: "registered",
			credential: { ...bare, backedUp: false },
			challengedAt: Date.now(),
		};
		expect((await post("verify", { response })).body).toEqual({
			credentialId: "Y3JlZA",
			backedUp: false,
		});
		expect(asked[1]).toEqual(["register", "sam", response, undefined, expect.any(Function)]);
		// Each passkey kept is recorded for the subject, with the source alone: no id, nickname or ceremony.
		const registered = { kind: "passkey.registered", subject: "sam", at: expect.any(Number) };
		const attributes = { source: "198.51.100.1" };
		expect(events).toEqual([
			{ ...registered, attributes },
			{ ...registered, attributes },
		]);
	});

	it("answers 401 without a session, and the requirement's answer when the session falls short", async () => {
		const { browser, asked } = await serve();
		const none = await browser();
		expect((await none("options")).body).toEqual({ error: "unauthorized" });
		expect((await none("verify", { response: {} })).status).toBe(401);
		const held = await browser("held-sam");
		expect(await held("options")).toMatchObject({
			status: 403,
			body: { error: "step_up_required" },
		});
		expect((await held("verify", { response: {} })).status).toBe(403);
		expect(asked).toEqual([]);
	});

	it("refuses a body without a response object, or with a nickname out of shape, before asking webauthn", async () => {
		const { browser, asked } = await serve();
		const post = await browser("sam");
		for (const body of [
			{},
			{ response: "x" },
			{ response: null },
			{ response: [] },
			{ response: {}, nickname: "" },
			{ response: {}, nickname: "x".repeat(65) },
			{ response: {}, nickname: "\u{1f511}".repeat(65) },
			{ response: {}, nickname: "desk\u0000top" },
			{ response: {}, nickname: "desk‮top" },
			{ response: {}, nickname: "desk⁦top" },
			{ response: {}, nickname: "x\ud800" },
			{ response: {}, nickname: 7 },
		]) {
			const answer = await post("verify", body);
			expect(answer.status, JSON.stringify(body)).toBe(400);
			expect(answer.body.error, JSON.stringify(body)).toBe("invalid_request");
		}
		expect((await post("verify")).body.error).toBe("invalid_request");
		expect((await post("verify", { response: {}, nickname: "x".repeat(64) })).status).toBe(200);
		expect((await post("verify", { response: {}, nickname: "\u{1f511}".repeat(64) })).status).toBe(
			200,
		);
		expect(asked).toHaveLength(2);
	});

	it("answers each refusal of webauthn in the words clients of these routes know, recording none", async () => {
		const { browser, state, events } = await serve();
		const post = await browser("sam");
		const answers = {
			origin: { error: "origin_mismatch" },
			"top-origin": { error: "top_origin_mismatch" },
			challenge: { error: "challenge_mismatch" },
			rp: { error: "rp_id_mismatch" },
			algorithm: { error: "algorithm_not_allowed" },
			signature: { error: "attestation_invalid" },
			malformed: { error: "unknown" },
			"user-verification": { error: "user_verification_required" },
			"sign-count": { error: "unknown" },
			"user-handle": { error: "unknown" },
			"backup-eligibility": { error: "unknown" },
			"no-challenge": { error: "challenge_invalid" },
			conflict: {
				error: "credential_id_conflict",
				error_description: "credential ID already registered",
			},
			full: { error: "credential_limit" },
			unreadable: { error: "invalid_request", error_description: "unreadable client data" },
			// `revoked` is answered as no session, apart.
		} satisfies Record<Exclude<RegistrationRefusal, "revoked">, Record<string, string>>;
		for (const [reason, body] of Object.entries(answers)) {
			state.answer = { kind: "refused", reason: reason as RegistrationRefusal };
			expect(await post("verify", { response: {} }), reason).toEqual({
				status: 400,
				body,
				cacheControl: "no-store",
			});
		}
		expect(events).toEqual([]);
	});

	it("answers 503 when webauthn cannot tell", async () => {
		const { browser, state } = await serve();
		const post = await browser("sam");
		state.down = true;
		const down = {
			status: 503,
			body: { error: "temporarily_unavailable" },
			cacheControl: "no-store",
		};
		expect(await post("options")).toEqual(down);
		expect(await post("verify", { response: {} })).toEqual(down);
	});

	it("refuses a request from another origin by the CSRF policy, and a form body", async () => {
		const { browser, asked } = await serve();
		const elsewhere = await browser("sam", "https://evil.example");
		expect(await elsewhere("options")).toMatchObject({ status: 403, body: { error: "csrf" } });
		const post = await browser("sam");
		expect((await post("verify", "response=x", "application/x-www-form-urlencoded")).status).toBe(
			415,
		);
		expect(asked).toEqual([]);
	});

	it("limits requests per source over both routes, then answers 429", async () => {
		const { browser } = await serve({ requests: 2, window: "1m" });
		const post = await browser("sam");
		expect((await post("options")).status).toBe(200);
		expect((await post("verify", { response: {} })).status).toBe(200);
		expect(await post("options")).toMatchObject({ status: 429, retryAfter: "60" });
		expect((await post("verify", { response: {} })).status).toBe(429);
	});
});

describe("the subject's passkeys from a session", () => {
	it("lists the session's subject's passkeys, without keys or counts, not cacheable", async () => {
		const { state, asked, browser } = await serve();
		state.listed = [
			{ id: "YQ", nickname: "laptop", backupEligible: false, backedUp: false, at: 5 },
			{ id: "Yg", transports: ["usb"], backupEligible: true, backedUp: true },
		];
		const res = await (await browser("sam"))(
			"/oauth/webauthn/registrations",
			undefined,
			undefined,
			"GET",
		);
		expect([res.status, res.body, res.cacheControl]).toEqual([
			200,
			{
				passkeys: [
					{
						credentialId: "YQ",
						nickname: "laptop",
						backupEligible: false,
						backedUp: false,
						createdAt: 5,
					},
					{ credentialId: "Yg", transports: ["usb"], backupEligible: true, backedUp: true },
				],
			},
			"no-store",
		]);
		expect(asked).toEqual([["listed", "sam"]]);
		const signedOut = await (await browser())(
			"/oauth/webauthn/registrations",
			undefined,
			undefined,
			"GET",
		);
		expect(signedOut.status).toBe(401);
	});

	it("renames one of the subject's passkeys, refusing a body out of shape and an id it does not hold", async () => {
		const { state, asked, browser, events } = await serve();
		const post = await browser("sam");
		const rename = (body: unknown) => post("/oauth/webauthn/registrations/rename", body);
		expect((await rename({ id: "YQ", nickname: "phone" })).status).toBe(200);
		expect(asked).toEqual([["renamed", "sam", "YQ", "phone"]]);
		for (const body of [{ nickname: "phone" }, { id: "YQ" }, { id: "YQ", nickname: "a\nb" }]) {
			expect((await rename(body)).body, JSON.stringify(body)).toMatchObject({
				error: "invalid_request",
			});
		}
		state.renamed = "unknown";
		expect(await rename({ id: "Zg", nickname: "x" })).toMatchObject({
			status: 404,
			body: { error: "not_found" },
		});
		expect(events.map((e) => [e.kind, e.subject])).toEqual([["passkey.renamed", "sam"]]);
		expect(JSON.stringify(events)).not.toMatch(/phone|YQ/);
	});

	it("removes one of the subject's passkeys, telling when it was the last", async () => {
		const { state, asked, browser, events } = await serve();
		const post = await browser("sam");
		const remove = (body: unknown) => post("/oauth/webauthn/registrations/remove", body);
		expect(await remove({ id: "YQ" })).toMatchObject({ status: 200, body: { last: false } });
		state.removed = { removed: true, empty: true };
		expect(await remove({ id: "Yg" })).toMatchObject({ status: 200, body: { last: true } });
		state.removed = { removed: false, empty: true };
		expect(await remove({ id: "Zg" })).toMatchObject({ status: 404, body: { error: "not_found" } });
		expect((await remove({})).body).toMatchObject({ error: "invalid_request" });
		expect(asked).toEqual([
			["removed", "sam", "YQ"],
			["removed", "sam", "Yg"],
			["removed", "sam", "Zg"],
		]);
		expect(events.map((e) => [e.kind, e.subject])).toEqual([
			["passkey.removed", "sam"],
			["passkey.removed", "sam"],
		]);
	});

	it("checks the origin and limits requests on renaming and removing too", async () => {
		const { browser } = await serve({ requests: 2, window: "1m" });
		const elsewhere = await browser("sam", "https://evil.example");
		for (const path of ["rename", "remove"]) {
			expect(
				await elsewhere(`/oauth/webauthn/registrations/${path}`, { id: "YQ", nickname: "x" }),
				path,
			).toMatchObject({ status: 403, body: { error: "csrf" } });
		}
		const post = await browser("kim");
		await post("/oauth/webauthn/registrations/rename", { id: "YQ", nickname: "x" });
		await post("/oauth/webauthn/registrations/remove", { id: "YQ" });
		expect(await post("/oauth/webauthn/registrations/remove", { id: "YQ" })).toMatchObject({
			status: 429,
		});
	});

	it("limits renaming alone too", async () => {
		const { browser } = await serve({ requests: 2, window: "1m" });
		const renaming = await browser("lee");
		const rename = (nickname: string) =>
			renaming("/oauth/webauthn/registrations/rename", { id: "YQ", nickname });
		expect((await rename("x")).status).toBe(200);
		expect((await rename("y")).status).toBe(200);
		expect(await rename("z")).toMatchObject({ status: 429 });
	});

	it("asks passkeys to keep nothing a revocation since its challenge reaches, answering unauthorized and recording no registration", async () => {
		const { state, asked, browser, events } = await serve();
		state.answer = {
			kind: "registered",
			credential,
			challengedAt: Date.now() - 1000,
		} as Registered;
		state.revokeWhileWriting = true;
		const post = await browser("sam");
		const res = await post("verify", { response: {} });
		expect([res.status, res.body]).toEqual([401, { error: "unauthorized" }]);
		expect(asked.at(-1)).toEqual(["register", "sam", {}, undefined, expect.any(Function)]);
		expect(events).toEqual([]);
	});
});
