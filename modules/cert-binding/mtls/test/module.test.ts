import { createHash } from "node:crypto";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { type MetadataItem, metadata } from "@mod/issuer";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	kernelConfig,
	type Runtime,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { type SignedOutbound, signedOutbound } from "@mod/outbound";
import { type Scene, senderBinding, senderBindings } from "@mod/sender-binding";
import senderBindingModule from "@mod/sender-binding/module";
import { describe, expect, it } from "vitest";
import mtls from "../src/module.ts";
import { crlOf, type Issued, issue, pemOf, rsaKeys } from "../src/pki/test/authority.ts";

const runtime = quietRuntime();
const thumbprint = (der: Uint8Array) => createHash("sha256").update(der).digest("base64url");

type Sent = Parameters<SignedOutbound["fetch"]>;

/** Signed material served from a table by URL, recording what was asked. */
function serving(table: Record<string, Uint8Array>, missing: number, sent: Sent[]) {
	const outbound: SignedOutbound = {
		fetch: async (...asked) => {
			sent.push(asked);
			const body = table[asked[0]];
			return { status: body ? 200 : missing, headers: new Map(), body: body ?? new Uint8Array() };
		},
	};
	return defineModule({ name: "signed-material", takes: [] }, (m) => [
		m.provide(signedOutbound).by(() => outbound),
	]);
}

const published = contract<readonly MetadataItem[]>("published");
const kindNames = contract<readonly (string | undefined)[]>("kind-names");
const reader = defineModule({ name: "reader", takes: [metadata, senderBindings] }, (m) => [
	m.provide(published).by((c) => c.collect(metadata)),
	m.provide(kindNames).by(async (c) => (await c.collect(senderBindings)).map((kind) => kind.name)),
]);

async function boot(
	section: unknown,
	{
		table = {},
		missing = 404,
		forwarding = true,
		run = runtime,
	}: {
		table?: Record<string, Uint8Array>;
		missing?: number;
		forwarding?: boolean;
		run?: Runtime;
	} = {},
) {
	const sent: Sent[] = [];
	const app = await assemble({
		modules: [http, issuerModule, senderBindingModule, reader, serving(table, missing, sent), mtls],
		config: {
			...kernelConfig(),
			...httpConfig(
				forwarding ? { "client-certificate": { dialect: "pem", header: "x-client-cert" } } : {},
			),
			...issuerConfig(),
			mtls: section,
		},
		runtime: run,
	});
	const bindingOf = (leaf: Issued, chain: Issued[] = [], scene: Scene = { kind: "issue" }) =>
		app.get(senderBinding).bindingOf(
			testRequest({
				method: "POST",
				path: "/oauth/token",
				source: {
					clientCertificate: {
						kind: "certificate",
						leaf: leaf.der,
						chain: chain.map((c) => c.der),
					},
				},
			}),
			scene,
		);
	return { app, bindingOf, sent };
}

async function pki() {
	const root = await issue({ cn: "root", ca: true });
	const intermediate = await issue({
		cn: "intermediate",
		by: root,
		ca: true,
		crl: "http://root.example/crl",
	});
	const client = await issue({
		cn: "client",
		by: intermediate,
		eku: ["1.3.6.1.5.5.7.3.2"],
		crl: "http://ca.example/crl",
	});
	const section = {
		mode: "pki",
		anchors: [pemOf(root.der)],
		revocation: {
			mode: "crl",
			"on-unavailable": "reject",
			hosts: ["ca.example", "root.example"],
		},
	};
	return { root, intermediate, client, section };
}

describe("mtls", () => {
	it("is named mtls, as operators name it in a client's requirement", async () => {
		const { app } = await boot({ mode: "self-signed" });
		expect(app.get(kindNames)).toEqual(["mtls"]);
	});

	it("binds a token to a self-signed certificate's thumbprint, as a bearer token [rfc8705-3.1-b] [rfc8705-3.1-c]", async () => {
		const { bindingOf } = await boot({ mode: "self-signed" });
		const own = await issue({ cn: "client" });
		expect(await bindingOf(own)).toEqual({
			kind: "bound",
			binding: { member: "x5t#S256", confirmation: thumbprint(own.der), tokenType: "Bearer" },
		});
	});

	it("binds under PKI a certificate whose path and revocation hold, and refuses a revoked one", async () => {
		const { root, intermediate, client, section } = await pki();
		const table = {
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		const { bindingOf } = await boot(section, { table });
		expect(await bindingOf(client, [intermediate])).toMatchObject({
			kind: "bound",
			binding: { confirmation: thumbprint(client.der) },
		});
		const revoked = await issue({
			cn: "client",
			by: intermediate,
			eku: ["1.3.6.1.5.5.7.3.2"],
			crl: "http://ca.example/crl",
		});
		const listing = await boot(section, {
			table: {
				...table,
				"http://ca.example/crl": await crlOf({ by: intermediate, revoked: [revoked] }),
			},
		});
		expect(await listing.bindingOf(revoked, [intermediate])).toMatchObject({
			kind: "refused",
			error: "invalid_client",
		});
		const resource = { kind: "resource", token: "t" } as const;
		expect(await listing.bindingOf(revoked, [intermediate], resource)).toMatchObject({
			kind: "refused",
			error: "invalid_token",
		});
	});

	it("binds a revoked certificate when revocation is disabled", async () => {
		const { intermediate, section } = await pki();
		const revoked = await issue({
			cn: "client",
			by: intermediate,
			eku: ["1.3.6.1.5.5.7.3.2"],
			crl: "http://ca.example/crl",
		});
		const table = {
			"http://ca.example/crl": await crlOf({ by: intermediate, revoked: [revoked] }),
		};
		const unchecked = await boot({ ...section, revocation: { mode: "disabled" } }, { table });
		expect(await unchecked.bindingOf(revoked, [intermediate])).toMatchObject({ kind: "bound" });
	});

	it("leaves a revocation outage to the operator, and asks the responder the section names", async () => {
		const { root, intermediate, client, section } = await pki();
		const down = { "http://root.example/crl": await crlOf({ by: root }) };
		const rejecting = await boot(section, { table: down, missing: 503 });
		expect(await rejecting.bindingOf(client, [intermediate])).toMatchObject({
			kind: "refused",
			error: "temporarily_unavailable",
		});
		const allow = { ...section.revocation, "on-unavailable": "allow" };
		const allowing = await boot({ ...section, revocation: allow }, { table: down, missing: 503 });
		expect(await allowing.bindingOf(client, [intermediate])).toMatchObject({ kind: "bound" });
		const served = { ...down, "http://ca.example/crl": await crlOf({ by: intermediate }) };
		expect(
			await (await boot(section, { table: served })).bindingOf(client, [intermediate]),
		).toMatchObject({
			kind: "bound",
		});
		// The client names no responder: under OCSP, the same certificate is refused.
		const ocsp = await boot(
			{ ...section, revocation: { ...section.revocation, mode: "ocsp" } },
			{ table: served },
		);
		expect(await ocsp.bindingOf(client, [intermediate])).toMatchObject({
			kind: "refused",
			error: "invalid_client",
		});
	});

	it("names among the issuer's metadata that it binds access tokens to certificates", async () => {
		const { app } = await boot({ mode: "self-signed" });
		expect(app.get(published)).toContainEqual({
			name: "tls_client_certificate_bound_access_tokens",
			value: true,
		});
	});

	it("refuses to boot without a mode, and under PKI without anchors or a stated revocation", async () => {
		const { root, section } = await pki();
		const { revocation } = section;
		// Without a place http reads forwarded certificates from, nothing would ever be bound.
		await expect(boot({ mode: "self-signed" }, { forwarding: false })).rejects.toBeInstanceOf(
			BootRefused,
		);
		for (const bad of [
			{},
			{ mode: "self-signed", anchors: [pemOf(root.der)] },
			{ mode: "pki", anchors: [pemOf(root.der)] },
			{ ...section, anchors: [] },
			{ ...section, anchors: ["not a certificate"] },
			{ ...section, anchors: [`${pemOf(root.der)}${pemOf(root.der)}`] },
			{ ...section, anchors: [`x${pemOf(root.der)}`] },
			{ ...section, anchors: [pemOf(new Uint8Array([1, 2, 3]))] },
			{ ...section, anchors: ["   "] },
			{ ...section, revocation: { mode: "crl", hosts: ["ca.example"] } },
			{ ...section, revocation: { ...revocation, "on-unavailable": undefined } },
			{ ...section, revocation: { ...revocation, hosts: [] } },
			{ ...section, revocation: { mode: "disabled", hosts: ["ca.example"] } },
			{ ...section, "min-rsa-bits": 1024 },
		]) {
			await expect(boot(bad), JSON.stringify(bad)).rejects.toBeInstanceOf(BootRefused);
		}
		const { bindingOf } = await boot(section);
		expect(bindingOf).toBeDefined();
	});

	it("holds the path to the section's limits", async () => {
		const { root, intermediate, client, section } = await pki();
		const disabled = { ...section, revocation: { mode: "disabled" } };
		const strict = await boot({ ...disabled, "max-intermediates": 0 });
		expect(await strict.bindingOf(client, [intermediate])).toMatchObject({ kind: "refused" });
		const bits = await boot({ ...disabled, "min-rsa-bits": 3072 });
		const rsa = await issue({ cn: "client", by: root, keys: await rsaKeys(2048) });
		expect(await bits.bindingOf(rsa)).toMatchObject({ kind: "refused" });
		expect(await (await boot(disabled)).bindingOf(rsa)).toMatchObject({ kind: "bound" });
	});

	it("asks for revocation material within the section's hosts and time", async () => {
		const { intermediate, client, section } = await pki();
		const reach = { ...section.revocation, timeout: "1234ms" };
		const reaching = await boot({ ...section, revocation: reach });
		await reaching.bindingOf(client, [intermediate]);
		expect(reaching.sent.map(([, , narrower]) => narrower)).toContainEqual({
			hosts: ["ca.example", "root.example"],
			timeoutMs: 1234,
		});
		expect(reaching.sent.every(([, , n]) => n.timeoutMs === 1234)).toBe(true);
	});

	it("judges the leaf's end and the CRL's next update by the runtime's clock, logging a refusal", async () => {
		const { root, intermediate, client, section } = await pki();
		const recorded = recordingLog();
		const at = (ms: number) =>
			quietRuntime({ clock: { now: () => Date.now() + ms }, log: recorded.log });
		const disabled = { ...section, revocation: { mode: "disabled" } };
		const late = await boot(disabled, { run: at(2 * 86_400_000) });
		expect(await late.bindingOf(client, [intermediate])).toMatchObject({ kind: "refused" });
		expect(
			recorded
				.lines()
				.filter((line) => line.level === "warn")
				.map((line) => line.event),
		).toEqual(["mtls.certificate_refused"]);
		const table = {
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		const stale = await boot(section, { table, run: at(2 * 3_600_000) });
		expect(await stale.bindingOf(client, [intermediate])).toMatchObject({ kind: "refused" });
	});

	it("uses the runtime's randomness as the OCSP nonce", async () => {
		const { intermediate, section } = await pki();
		const asking = await issue({
			cn: "client",
			by: intermediate,
			eku: ["1.3.6.1.5.5.7.3.2"],
			ocsp: "http://ca.example/ocsp",
		});
		const random = quietRuntime({ random: { bytes: (n: number) => new Uint8Array(n).fill(5) } });
		const ocsp = { ...section, revocation: { ...section.revocation, mode: "ocsp" } };
		const nonced = await boot(ocsp, { run: random });
		await nonced.bindingOf(asking, [intermediate]);
		const [, request] = nonced.sent[0] ?? [];
		const body = request?.method === "POST" ? request.body : undefined;
		expect(Buffer.from(body ?? "").includes(Buffer.from(new Uint8Array(16).fill(5)))).toBe(true);
	});
});
