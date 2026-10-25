import { type AuditReceiver, audit, auditReceivers } from "@mod/audit";
import auditModule from "@mod/audit/module";
import { assemble, BootRefused, contract, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import {
	DestinationRefused,
	type Narrower,
	type OutboundRequest,
	type OutboundResponse,
	outbound,
} from "@mod/outbound";
import { credentialPolicy, credentialRefusalText, outboundRefusals } from "@mod/outbound-policy";
import { beforeEach, expect, it } from "vitest";
import auditHttp from "../src/module.ts";
import { auditHttpConfig } from "../src/testing.ts";

/** How outbound explains a host its allow list leaves out. */
const notAllowed = "not-allowed: name the host in outbound.allow, or set outbound.allow-any-public";
const runtime = quietRuntime({
	clock: { now: () => 1234 },
	random: { bytes: (n) => new Uint8Array(n) },
});
const sent: { url: string; request: OutboundRequest | undefined; narrower?: Narrower }[] = [];
const checked: (Narrower | undefined)[] = [];
beforeEach(() => {
	sent.length = 0;
	checked.length = 0;
});
/** A host the policy of the outbound below refuses. */
const elsewhere = "elsewhere.example";
/** An outbound that keeps each request and answers as the test says. */
const outboundAnswering = (answer: () => Promise<OutboundResponse>) =>
	defineModule({ name: "outbound", takes: [] }, (m) => [
		m.provide(outbound).by(() => ({
			fetch: async (url, request, narrower) => {
				sent.push({ url, request, ...(narrower ? { narrower } : {}) });
				return answer();
			},
		})),
		m.provide(outboundRefusals).by(() => ({
			explained: (url, narrower) => {
				checked.push(narrower);
				return new URL(url).hostname === elsewhere ? notAllowed : undefined;
			},
		})),
		// As outbound's rule reads, with 127.0.0.1 standing for a named plain-loopback pair.
		m.provide(credentialPolicy).by(() => ({
			refusalOf: (urls) =>
				urls.every((u) => u.startsWith("https://") || u.startsWith("http://127.0.0.1:"))
					? undefined
					: "scheme",
		})),
	]);
const status = (code: number) => async () => ({
	status: code,
	headers: new Map(),
	body: new Uint8Array(),
});
const boot = async (answer: () => Promise<OutboundResponse>, section: unknown) =>
	(
		await assemble({
			modules: [auditModule, outboundAnswering(answer), auditHttp],
			config: {
				...kernelConfig(),
				audit: { receivers: ["http"] },
				...(section === undefined ? {} : { "audit-http": section }),
			},
			runtime,
		})
	).get(audit);
const settled = () => new Promise((resolve) => setTimeout(resolve, 0));
const url = "https://audit.example/events";

it("posts each event as one JSON object to the operator's URL", async () => {
	const a = await boot(status(204), { url });
	a.record({ kind: "login.succeeded", subject: "s", attributes: { method: "password" } });
	a.record({ kind: "login.failed" });
	await settled();
	expect(sent.map((s) => s.url)).toEqual([url, url]);
	expect(sent[0]?.request?.method).toBe("POST");
	expect(sent[0]?.request?.headers).toEqual({ "content-type": "application/json" });
	expect(sent.map((s) => JSON.parse(String(s.request?.body)))).toEqual([
		{ kind: "login.succeeded", subject: "s", attributes: { method: "password" }, at: 1234 },
		{ kind: "login.failed", at: 1234 },
	]);
});

it("names its URL as the operator's own, at boot and on each post, so a collector at a private address is reached", async () => {
	const a = await boot(status(204), { url });
	a.record({ kind: "login.failed" });
	await settled();
	expect(checked).toEqual([{ internal: url }]);
	expect(sent.map((s) => s.narrower)).toEqual([{ internal: url }]);
});

it("sends the collector's Authorization header where the operator gives one, and only then", async () => {
	const secret = "Bearer s3cr3t-token";
	(await boot(status(204), { url, authorization: secret })).record({ kind: "k" });
	(await boot(status(204), { url })).record({ kind: "k" });
	await settled();
	expect(sent.map((s) => s.request)).toMatchObject([
		{ headers: { "content-type": "application/json" }, credential: secret },
		{ headers: { "content-type": "application/json" } },
	]);
	// outbound sends the credential as the header; audit-http writes none of its own.
	expect(sent.map((s) => s.request?.headers?.authorization)).toEqual([undefined, undefined]);
	expect(sent[1]?.request?.credential).toBeUndefined();
});

it("sends the test builder's Authorization value to its https URL", async () => {
	const section = auditHttpConfig()["audit-http"];
	(await boot(status(204), section)).record({ kind: "k" });
	await settled();
	expect(section.url).toMatch(/^https:\/\//);
	expect(sent.map((s) => [s.url, s.request?.credential])).toEqual([
		[section.url, section.authorization],
	]);
});

it("refuses the fragment's placeholder for the Authorization value, without telling it", async () => {
	const placeholder = "REPLACE-AUTHORIZATION-HEADER-VALUE";
	const refused = await boot(status(204), { url, authorization: placeholder }).catch((e) => e);
	expect(refused).toBeInstanceOf(BootRefused);
	expect(refused.refusals.map((r: { where: string }) => r.where)).toEqual([
		"audit-http.authorization",
	]);
	expect(JSON.stringify(refused.refusals)).not.toContain(placeholder);
});

it("refuses an Authorization value that is not printable ASCII on one line, without telling it", async () => {
	const secret = "Bearer s3cr3t\r\nx-injected: 1";
	const refused = await boot(status(204), { url, authorization: secret }).catch((error) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	expect(JSON.stringify(refused.refusals)).not.toContain("s3cr3t");
	const others = {
		empty: "",
		"a leading space": " Bearer x",
		"a trailing space": "Bearer x ",
		"not ASCII": "Bearer \u00e9",
	};
	for (const [name, value] of Object.entries(others)) {
		await expect(boot(status(204), { url, authorization: value }), name).rejects.toBeInstanceOf(
			BootRefused,
		);
	}
});

it("refuses a secret Authorization value with a URL outbound will not send a credential to, and takes a named plain-loopback collector", async () => {
	const plain = { url: "http://audit.example/events", authorization: "Bearer s3cr3t" };
	await expect(boot(status(204), plain)).rejects.toMatchObject({
		refusals: [
			{
				where: "audit-http.url",
				reason: `a secret Authorization value ${credentialRefusalText("scheme")}`,
			},
		],
	});
	await expect(boot(status(204), { url: plain.url })).resolves.toBeDefined();
	const local = { url: "http://127.0.0.1:9000/events", authorization: "Bearer s3cr3t" };
	await expect(boot(status(204), local)).resolves.toBeDefined();
});

it("takes outbound's credential policy only with an Authorization value, its takes naming it either way", async () => {
	const unused = async (section: unknown) =>
		(
			await takesUnused({
				modules: [auditModule, outboundAnswering(status(204)), auditHttp],
				config: { ...kernelConfig(), audit: { receivers: ["http"] }, "audit-http": section },
				runtime,
			})
		)["audit-http"];
	expect(await unused({ url, authorization: "Bearer s3cr3t-token" })).toBeUndefined();
	// The takes are static: outbound provides the policy beside the refusals the module always
	// takes, so wherever it boots the policy is there, and without a value it is left untaken.
	expect(await unused({ url })).toEqual(["outbound.credentials"]);
});

it("refuses boot on a URL outbound's policy refuses, saying why", async () => {
	const booting = boot(status(204), { url: `https://${elsewhere}/events` });
	await expect(booting).rejects.toMatchObject({
		refusals: [
			{
				where: "audit-http.url",
				reason: `outbound's destination policy refuses it: ${notAllowed}`,
			},
		],
	});
});

/** The receiver `http` itself, over an outbound answering as the test says. */
const receiverOf = async (answer: () => Promise<OutboundResponse>, section: unknown) => {
	const receivers = contract<readonly AuditReceiver[]>("test.receivers");
	const app = await assemble({
		modules: [
			outboundAnswering(answer),
			auditHttp,
			defineModule({ name: "peek", takes: [auditReceivers] }, (m) => [
				m.provide(receivers).by((c) => c.collect(auditReceivers)),
			]),
		],
		config: { ...kernelConfig(), "audit-http": section },
		runtime,
	});
	return app.get(receivers)[0] as AuditReceiver;
};

it("fails on a redirect outbound refuses or a server error, never telling the secret", async () => {
	const secret = "Bearer s3cr3t-token";
	const answers = {
		"a redirect, refused by outbound": async (): Promise<OutboundResponse> => {
			throw new DestinationRefused("redirect");
		},
		"a server error": status(500),
	};
	for (const [name, answer] of Object.entries(answers)) {
		const receiver = await receiverOf(answer, { url, authorization: secret });
		const failure = await receiver.receive({ kind: "k", at: 1 }).catch((error) => error);
		expect(failure, name).toBeInstanceOf(Error);
		expect(String(failure), name).not.toContain("s3cr3t");
	}
	expect(sent.map((s) => s.url)).toEqual([url, url]);
});

it("fails as a receiver when the answer is not a success, or nothing usable comes back", async () => {
	for (const answer of [
		status(500),
		status(304),
		async () => {
			throw new Error("unreachable");
		},
	]) {
		const a = await boot(answer, { url });
		a.record({ kind: "k" });
		await settled();
		expect(a.lost()).toEqual({ http: 1 });
	}
	const fine = await boot(status(200), { url });
	fine.record({ kind: "k" });
	await settled();
	expect(fine.lost()).toEqual({ http: 0 });
});

it("refuses to start without a URL, or with one it could not post to as written", async () => {
	const refused: Record<string, unknown> = {
		"no section": undefined,
		"no url": {},
		"another scheme": { url: "ftp://audit.example/events" },
		"no URL": { url: "not a url" },
		"user information": { url: "https://u:p@audit.example/events" },
		"a fragment": { url: "https://audit.example/events#x" },
		"an upper-case scheme": { url: "HTTPS://audit.example/events" },
		"surrounding space": { url: " https://audit.example/events" },
		"another member": { url, other: 1 },
	};
	for (const [name, section] of Object.entries(refused)) {
		await expect(boot(status(204), section), name).rejects.toBeInstanceOf(BootRefused);
	}
});
