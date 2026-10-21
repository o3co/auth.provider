import { randomBytes } from "node:crypto";
import { listening } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig } from "@mod/http/testing";
import { assemble, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import type { Verification } from "@mod/webauthn";
import webauthn from "@mod/webauthn/module";
import {
	type Client,
	type CreationOptions,
	testCeremonies as ceremoniesFor,
	softwareAuthenticator,
	type Twist,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { expect, it } from "vitest";
import { registrations } from "../src/contract.ts";
import passkeysModule from "../src/module.ts";
import { keptChallenges, keptPasskeys } from "../src/records.ts";
import { registrationsOver } from "../src/registration/registrations.ts";
import { passkeysConfig } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

type Options = CreationOptions & { excludeCredentials: { id: string }[] };

/** Registrations over memory stores, for a relying party framed only by `shell.example`. */
function kept({
	verification = "preferred" as Verification,
	max = 10,
	now = Date.now as () => number,
} = {}) {
	// The stores keep the host's time; `now` is kernel's, which a test may move apart from it.
	const stores = memoryStores(() => Date.now());
	const rp = {
		id: "rp.example",
		name: "RP",
		origins: [testOrigin],
		topOrigins: ["https://shell.example"],
		timeoutMs: 120_000,
	};
	const random = (n: number) => new Uint8Array(randomBytes(n));
	const registrations = registrationsOver({
		ceremonies: ceremoniesFor(rp, random, now),
		records: keptPasskeys(stores.passkeys, now),
		challenges: keptChallenges(stores.challenges, now, 120_000),
		verification,
		max,
		freshHandle: () => randomBytes(32).toString("base64url"),
	});
	/** Asks options for `subject` and answers them with `authenticator`. */
	const register = async (
		subject: string,
		{
			authenticator = softwareAuthenticator(),
			twist = {},
			client = {},
		}: {
			authenticator?: ReturnType<typeof softwareAuthenticator>;
			twist?: Twist;
			client?: Partial<Client>;
		} = {},
	) => {
		const options = (await registrations.creation(subject)).options as Options;
		const response = authenticator.create(options, { origin: testOrigin, ...client }, twist);
		return {
			options,
			response,
			answer: await registrations.register(subject, response, "laptop"),
		};
	};
	return { stores, registrations, register };
}

it("registers a passkey for the subject under one handle, and excludes it from the next options", async () => {
	const { registrations, register } = kept();
	const first = await register("sam");
	expect(first.answer).toMatchObject({
		kind: "registered",
		credential: {
			id: first.response.id,
			userHandle: first.options.user.id,
			transports: ["internal"],
			backedUp: false,
		},
	});
	const next = (await registrations.creation("sam")).options as Options;
	expect(next.user.id).toBe(first.options.user.id);
	expect(next.excludeCredentials.map((c) => c.id)).toEqual([first.response.id]);
});

it("answers when the challenge a registration answered was made, and lists, renames and removes what the subject holds", async () => {
	const { registrations, register } = kept({ now: () => 7_000 });
	const { answer, response } = await register("sam");
	expect(answer).toMatchObject({ kind: "registered", challengedAt: 7_000 });
	expect(await registrations.listed?.("sam")).toEqual([
		expect.objectContaining({ id: response.id, nickname: "laptop", at: 7_000 }),
	]);
	expect(await registrations.renamed?.("sam", response.id, "phone")).toBe("renamed");
	expect(await registrations.renamed?.("kim", response.id, "mine")).toBe("unknown");
	expect(await registrations.removed?.("sam", response.id)).toEqual({ removed: true, empty: true });
	expect(await registrations.listed?.("sam")).toEqual([]);
});

it("takes a challenge once, and only for the subject it was made for", async () => {
	const { registrations, register } = kept();
	const { response } = await register("sam");
	expect(await registrations.register("sam", response)).toEqual({
		kind: "refused",
		reason: "no-challenge",
	});
	const options = (await registrations.creation("sam")).options as Options;
	await registrations.creation("kim");
	const answered = softwareAuthenticator().create(options, { origin: testOrigin });
	expect(await registrations.register("kim", answered)).toEqual({
		kind: "refused",
		reason: "no-challenge",
	});
});

it("refuses client data it cannot read before taking any challenge", async () => {
	const { registrations, stores } = kept();
	stores.down.challenges.failNext("take");
	expect(await registrations.register("sam", { response: {} })).toEqual({
		kind: "refused",
		reason: "unreadable",
	});
});

it("refuses an origin or a frame not listed, as the ceremony refuses it", async () => {
	const { register } = kept();
	const elsewhere = await register("sam", {
		client: { origin: "https://evil.example" },
		twist: { overlook: true },
	});
	expect(elsewhere.answer).toEqual({ kind: "refused", reason: "origin" });
	const framed = { crossOrigin: true, topOrigin: "https://evil.example" };
	expect((await register("sam", { client: framed })).answer).toEqual({
		kind: "refused",
		reason: "top-origin",
	});
});

it("refuses a response without user verification when it is required", async () => {
	const { register } = kept({ verification: "required" });
	const unverified = await register("sam", {
		authenticator: softwareAuthenticator({ userVerified: false }),
		twist: { overlook: true },
	});
	expect(unverified.answer).toEqual({ kind: "refused", reason: "user-verification" });
});

it("refuses a credential id another subject holds as a conflict, and keeps it theirs", async () => {
	const { registrations, register } = kept();
	const first = await register("sam");
	const copied = await register("kim", { twist: { credentialId: first.response.id } });
	expect(copied.answer).toEqual({ kind: "refused", reason: "conflict" });
	const again = (await registrations.creation("sam")).options as Options;
	expect(again.excludeCredentials.map((c) => c.id)).toEqual([first.response.id]);
});

it("keeps at most the subject's limit", async () => {
	const { register } = kept({ max: 1 });
	expect((await register("sam")).answer.kind).toBe("registered");
	expect((await register("sam")).answer).toEqual({ kind: "refused", reason: "full" });
});

it("throws unavailable when a store cannot tell", async () => {
	const { registrations, stores } = kept();
	stores.down.subjects.failNext("save");
	await expect(registrations.creation("sam")).rejects.toSatisfy(isUnavailable);
	const options = (await registrations.creation("sam")).options as Options;
	const response = softwareAuthenticator().create(options, { origin: testOrigin });
	stores.down.challenges.failNext("take");
	await expect(registrations.register("sam", response)).rejects.toSatisfy(isUnavailable);
});

it("offers registrations in a composition without a session, and serves no route of its own", async () => {
	const app = await assemble({
		modules: [http, memoryStores().module, webauthn, passkeysModule],
		config: { ...kernelConfig(), ...httpConfig(), ...webauthnConfig(), ...passkeysConfig() },
		runtime: quietRuntime(),
	});
	await app.start();
	try {
		expect((await app.get(registrations).creation("sam")).options).toMatchObject({
			rp: { id: "rp.example" },
		});
		const base = `http://127.0.0.1:${app.get(listening).port()}`;
		const res = await fetch(`${base}/oauth/webauthn/registration/options`, { method: "POST" });
		expect(res.status).toBe(404);
	} finally {
		await app.stop(1000);
	}
});

it("gives a ceremony the challenge lifetime the operator sets", async () => {
	const app = await assemble({
		modules: [http, memoryStores().module, webauthn, passkeysModule],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...webauthnConfig({ "challenge-lifetime": "30s" }),
			...passkeysConfig(),
		},
		runtime: quietRuntime(),
	});
	await app.start();
	try {
		const { options } = await app.get(registrations).creation("sam");
		expect(options).toMatchObject({ timeout: 30_000 });
	} finally {
		await app.stop(1000);
	}
});

it("refuses a challenge past its end on kernel's clock, whatever the store's clock says", async () => {
	let shift = 0;
	const { registrations } = kept({ now: () => Date.now() + shift });
	const options = (await registrations.creation("sam")).options as Options;
	const response = softwareAuthenticator().create(options, { origin: testOrigin });
	shift = 120_000;
	expect(await registrations.register("sam", response, "laptop")).toEqual({
		kind: "refused",
		reason: "no-challenge",
	});
});
