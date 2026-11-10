import { crlOf, ecKeys, issue, ocspOf, rsaKeys } from "@mod/x509-path/testing";
import { expect, it } from "vitest";
import type { Fetched, RevocationPolicy } from "../contract.ts";
import { isCertificate, pkiOver, signatureAlgorithms } from "../pki.ts";

const revocation = (served: Record<string, Uint8Array | "down">) => ({
	policy: {
		mode: "crl",
		nonce: true,
		skewMs: 300_000,
		ocspFreshMs: 600_000,
		crlTtlMs: 3_600_000,
		failureMs: 30_000,
		timeoutMs: 3000,
		crlEntries: 8,
		ocspEntries: 8,
		maxFetches: 4,
	} satisfies RevocationPolicy,
	sources: {
		fetch: async (url: string): Promise<Fetched> => {
			const body = served[url];
			if (body === "down") return { kind: "outage" };
			return body ? { kind: "material", body } : { kind: "refused" };
		},
		now: () => Date.now(),
		random: (n: number) => new Uint8Array(n),
	},
});

it("tells a path valid, invalid, revoked, or held up by an outage of its sources", async () => {
	const root = await issue({ cn: "root", ca: true });
	const client = await issue({ cn: "client", by: root, crl: "http://ca.example/crl" });
	const policy = {
		anchors: [root.der],
		maxIntermediates: 4,
		minRsaBits: 2048,
		signatureAlgorithms,
	};
	const check = (served?: Record<string, Uint8Array | "down">) =>
		pkiOver(policy, served && revocation(served)).check(client.der, [], Date.now());
	expect(await check()).toEqual({ kind: "valid" });
	expect(await check({ "http://ca.example/crl": await crlOf({ by: root }) })).toEqual({
		kind: "valid",
	});
	const listing = await crlOf({ by: root, revoked: [client] });
	expect(await check({ "http://ca.example/crl": listing })).toEqual({ kind: "revoked" });
	expect(await check({ "http://ca.example/crl": "down" })).toEqual({
		kind: "outage",
		reason: "unreachable",
	});
	expect(await check({})).toEqual({ kind: "invalid", reason: "source refused" });
	const stranger = await issue({ cn: "client", keys: await ecKeys() });
	expect(await pkiOver(policy).check(stranger.der, [], Date.now())).toEqual({
		kind: "invalid",
		reason: "path",
	});
});

it("holds an OCSP responder to the path's RSA bits", async () => {
	const root = await issue({ cn: "root", ca: true });
	const client = await issue({ cn: "client", by: root, ocsp: "http://ca.example/ocsp" });
	const responder = await issue({
		cn: "responder",
		by: root,
		eku: ["1.3.6.1.5.5.7.3.9"],
		noCheck: true,
		keys: await rsaKeys(2048),
	});
	const answer = await ocspOf({ cert: client, issuer: root, by: responder, certs: [responder] });
	const { policy, sources } = revocation({ "http://ca.example/ocsp": answer });
	const ocsp = { policy: { ...policy, mode: "ocsp", nonce: false } as const, sources };
	const check = (minRsaBits: number) =>
		pkiOver(
			{ anchors: [root.der], maxIntermediates: 4, minRsaBits, signatureAlgorithms },
			ocsp,
		).check(client.der, [], Date.now());
	expect(await check(2048)).toEqual({ kind: "valid" });
	expect(await check(3072)).toEqual({ kind: "invalid", reason: "signer" });
});

it("tells one certificate from anything else", async () => {
	const one = await issue({ cn: "one" });
	expect([isCertificate(one.der), isCertificate(new Uint8Array([1, 2]))]).toEqual([true, false]);
	expect(isCertificate(new Uint8Array([...one.der, 0]))).toBe(false);
});

it("refuses, in bounded time, a client's chain that cycles between two issuers, and an edge only its key identifier and signature join", async () => {
	const root = await issue({ cn: "root", ca: true, keyIds: true });
	const pki = pkiOver({
		anchors: [root.der],
		maxIntermediates: 4,
		minRsaBits: 2048,
		signatureAlgorithms,
	});
	// Two issuers that name and sign each other, as a client may send them; no anchor above.
	const y = await issue({ cn: "Y", ca: true });
	const x = await issue({ cn: "X", by: { ...y, cn: "Y" }, ca: true });
	const yByX = await issue({ cn: "Y", by: { ...x, cn: "X" }, ca: true, keys: y.keys });
	const cycled = await issue({ cn: "client", by: x, eku: ["1.3.6.1.5.5.7.3.2"] });
	const started = performance.now();
	expect(await pki.check(cycled.der, [x.der, yByX.der], Date.now())).toEqual({
		kind: "invalid",
		reason: "path",
	});
	expect(performance.now() - started).toBeLessThan(1000);
	// Self-issued "A", its key identifier the root's and signed by it, yet not the root's by name.
	const posing = await issue({ cn: "A", issuerName: "A", by: root, ca: true, keyIds: true });
	const under = await issue({ cn: "client", by: posing, keyIds: true, eku: ["1.3.6.1.5.5.7.3.2"] });
	expect(await pki.check(under.der, [posing.der], Date.now())).toEqual({
		kind: "invalid",
		reason: "path",
	});
});

it("holds the leaf alone to client authentication: its extended key usage, and its key usage, where given, to signing or key agreement", async () => {
	const clientAuth = "1.3.6.1.5.5.7.3.2";
	const serverAuth = "1.3.6.1.5.5.7.3.1";
	const root = await issue({ cn: "root", ca: true });
	const pki = pkiOver({
		anchors: [root.der],
		maxIntermediates: 4,
		minRsaBits: 2048,
		signatureAlgorithms,
	});
	const checked = async (leaf: { der: Uint8Array }, chain: { der: Uint8Array }[] = []) =>
		pki.check(
			leaf.der,
			chain.map((one) => one.der),
			Date.now(),
		);
	const refused = { kind: "invalid", reason: "not for client authentication" };
	expect(await checked(await issue({ cn: "client", by: root, eku: [serverAuth] }))).toEqual(
		refused,
	);
	// Key encipherment alone.
	const enciphering = await issue({ cn: "client", by: root, eku: [clientAuth], keyUsage: 0x20 });
	expect(await checked(enciphering)).toEqual(refused);
	for (const keyUsage of [0x80, 0x08]) {
		const leaf = await issue({ cn: "client", by: root, eku: [clientAuth], keyUsage });
		expect(await checked(leaf)).toEqual({ kind: "valid" });
	}
	// An intermediate for server authentication alone: the leaf alone is held to the purpose.
	const intermediate = await issue({ cn: "intermediate", by: root, ca: true, eku: [serverAuth] });
	const under = await issue({ cn: "client", by: intermediate, eku: [clientAuth] });
	expect(await checked(under, [intermediate])).toEqual({ kind: "valid" });
});
