import cookiesModule from "@mod/cookies/module";
import { csrfStandIn } from "@mod/csrf/testing";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, Unavailable } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { rateLimitStandIn } from "@mod/rate-limit/testing";
import { entryRequirements, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { type RegistrationRefusal, type Registrations, registrations } from "@mod/webauthn";
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
	const state = { answer: { kind: "registered", credential } as Registered, down: false };
	const asked: unknown[][] = [];
	const standIn = defineModule({ name: "webauthn" }, (m) => [
		m.provide(registrations).by(() => ({
			creation: async (subject) => {
				asked.push(["creation", subject]);
				if (state.down) throw new Unavailable("webauthn");
				return { options: { for: subject } };
			},
			register: async (...args) => {
				asked.push(["register", ...args]);
				if (state.down) throw new Unavailable("webauthn");
				return state.answer;
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			csrfStandIn,
			cookiesModule,
			sessionStandIn,
			subjectRevocationStandIn,
			rateLimitStandIn,
			holding,
			standIn,
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
	const base = `http://127.0.0.1:${app.get(listening).port()}`;
	/** A browser signed in as `subject`, or none, posting from `from`. */
	const browser = async (subject?: string, from = origin) => {
		const done = subject
			? await app
					.get(sessions)
					.complete(testRequest(), { subject, amr: ["pwd"], authenticatedAt: runtime.clock.now() })
			: undefined;
		const cookie = (done?.cookies ?? []).map((c) => c.split(";")[0]).join("; ");
		return async (path: string, body?: unknown, type = "application/json") => {
			const res = await fetch(`${base}/oauth/webauthn/registration/${path}`, {
				method: "POST",
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
	return { state, asked, browser };
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
		const { browser, asked, state } = await serve();
		const post = await browser("sam");
		const response = { id: "Y3JlZA", subject: "kim" };
		expect(await post("verify", { response, nickname: "laptop", subject: "kim" })).toMatchObject({
			status: 200,
			body: { credentialId: "Y3JlZA", transports: ["internal", "hybrid"], backedUp: true },
			cacheControl: "no-store",
		});
		expect(asked).toEqual([["register", "sam", response, "laptop"]]);
		const { transports: _, ...bare } = credential;
		state.answer = { kind: "registered", credential: { ...bare, backedUp: false } };
		expect((await post("verify", { response })).body).toEqual({
			credentialId: "Y3JlZA",
			backedUp: false,
		});
		expect(asked[1]).toEqual(["register", "sam", response, undefined]);
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

	it("answers each refusal of webauthn in the words clients of these routes know", async () => {
		const { browser, state } = await serve();
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
		} satisfies Record<RegistrationRefusal, Record<string, string>>;
		for (const [reason, body] of Object.entries(answers)) {
			state.answer = { kind: "refused", reason: reason as RegistrationRefusal };
			expect(await post("verify", { response: {} }), reason).toEqual({
				status: 400,
				body,
				cacheControl: "no-store",
			});
		}
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
