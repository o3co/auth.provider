import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { assemble, kernelConfig } from "@mod/kernel";
import { credentialPolicy } from "@mod/outbound-policy";
import { afterAll, beforeAll, expect, it } from "vitest";
import { DestinationRefused } from "../src/contract.ts";
import outboundModule, { outboundOver, section } from "../src/module.ts";
import type { Resolver } from "../src/transport.ts";

let server: Server;
let port = 0;
const seen: IncomingMessage["headers"][] = [];

beforeAll(async () => {
	server = createServer((req, res) => {
		seen.push(req.headers);
		res.end();
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", done));
	port = (server.address() as AddressInfo).port;
});
afterAll(() => new Promise<void>((done) => server.close(() => done())));

const resolve: Resolver = async () => ["127.0.0.1"];
const over = () =>
	outboundOver(
		section.parse({
			"allow-any-public": true,
			"plain-loopback": [`127.0.0.1:${port}`],
			"plain-internal": ["ledger.internal:9092"],
		}),
		resolve,
	);
const secret = "Bearer s3cr3t-0123456789";
/** What a refusal says, apart from what it is. */
const said = (run: Promise<unknown>) =>
	run.then(
		() => "sent",
		(error: Error) => `${error.name}: ${error.message}`,
	);

it("sends a credential as the request's Authorization, to a named plain-loopback pair", async () => {
	await over().fetch(`http://127.0.0.1:${port}/`, { credential: secret });
	expect(seen.at(-1)?.authorization).toBe(secret);
});

it("refuses a credential beside an Authorization header of any case, or one that is no single line, telling neither value", async () => {
	const before = seen.length;
	const url = `http://127.0.0.1:${port}/`;
	for (const request of [
		{ credential: secret, headers: { Authorization: "Basic other-value" } },
		{ credential: secret, headers: { authorization: "Basic other-value" } },
		{ credential: `${secret}\r\nX-Injected: 1` },
		{ credential: "" },
		{ credential: ` ${secret}` },
	]) {
		const told = await said(over().fetch(url, request));
		expect(told, JSON.stringify(request)).toMatch(/^TypeError: outbound: /);
		expect(told).not.toContain("s3cr3t");
		expect(told).not.toContain("other-value");
	}
	expect(seen.length).toBe(before);
});

it("refuses an Authorization header a caller writes, in any case and with no credential, signed material too, telling no value", async () => {
	const before = seen.length;
	const plain = `http://127.0.0.1:${port}/`;
	for (const headers of [
		{ AuThOrIzAtIoN: secret },
		{ authorization: secret },
		{ Authorization: secret, authorization: "Basic other-value" },
	]) {
		for (const run of [
			over().fetch(plain, { headers }),
			over().fetchSigned("http://public.example/", { headers }, { hosts: ["public.example"] }),
		]) {
			const told = await said(run);
			expect(told, JSON.stringify(Object.keys(headers))).toMatch(/^TypeError: outbound: /);
			expect(told).not.toContain("s3cr3t");
			expect(told).not.toContain("other-value");
		}
	}
	expect(seen.length).toBe(before);
});

it("never sends a credential for signed material, which may go over plain http", async () => {
	const before = seen.length;
	const signed = over().fetchSigned(`http://127.0.0.1:${port}/`, { credential: secret } as never, {
		hosts: ["127.0.0.1"],
	});
	await expect(signed).rejects.toEqual(new DestinationRefused("credential"));
	expect(await said(signed)).not.toContain("s3cr3t");
	expect(seen.length).toBe(before);
});

it("answers at boot why a credential must not go to a set of URLs: more than one origin, or neither https nor a named plain-loopback or plain-internal pair", () => {
	const policy = { credentialRefusalOf: over().credentialRefusalOf };
	const plain = `http://127.0.0.1:${port}`;
	expect(policy.credentialRefusalOf([])).toBeUndefined();
	expect(
		policy.credentialRefusalOf(["https://a.example/v", "https://a.example/s?x=1"]),
	).toBeUndefined();
	expect(policy.credentialRefusalOf([`${plain}/v`, `${plain}/s`])).toBeUndefined();
	expect(policy.credentialRefusalOf(["http://ledger.internal:9092/v"])).toBeUndefined();
	expect(policy.credentialRefusalOf(["http://ledger.internal:9093/v"])).toBe("scheme");
	expect(policy.credentialRefusalOf(["https://a.example/v", "https://b.example/s"])).toBe(
		"origins",
	);
	expect(policy.credentialRefusalOf(["https://a.example/v", "https://a.example:8443/s"])).toBe(
		"origins",
	);
	expect(policy.credentialRefusalOf(["http://a.example/v"])).toBe("scheme");
	expect(policy.credentialRefusalOf([`http://127.0.0.1:${port + 1}/v`])).toBe("scheme");
});

it("offers the same answer at boot as outbound.credentials", async () => {
	const app = await assemble({
		modules: [outboundModule],
		config: {
			...kernelConfig(),
			outbound: { "allow-any-public": true, "direct-despite-proxy": true },
		},
	});
	const policy = app.get(credentialPolicy);
	expect(policy.refusalOf(["https://a.example/v", "https://b.example/s"])).toBe("origins");
	expect(policy.refusalOf(["https://a.example/v"])).toBeUndefined();
});
