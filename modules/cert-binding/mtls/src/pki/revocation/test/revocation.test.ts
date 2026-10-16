import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import type { Fetched, PathPolicy, RevocationPolicy } from "../../contract.ts";
import {
	type Answering,
	crlOf,
	ecKeys,
	type Issued,
	issue,
	ocspOf,
	pointAt,
	rsaKeys,
} from "../../test/authority.ts";
import { revocationOver } from "../revocation.ts";

const ocspSigning = "1.3.6.1.5.5.7.3.9";
type Policy = RevocationPolicy & Pick<PathPolicy, "minRsaBits">;
const policyOf = (more: Partial<Policy> = {}): Policy => ({
	mode: "crl",
	nonce: true,
	skewMs: 300_000,
	ocspFreshMs: 600_000,
	crlTtlMs: 3_600_000,
	failureMs: 30_000,
	crlEntries: 256,
	ocspEntries: 1024,
	maxFetches: 4,
	minRsaBits: 2048,
	...more,
});

/** The nonce a request carries, if any. */
function nonceOf(body: Uint8Array): Uint8Array | undefined {
	const request = new pkijs.OCSPRequest({ schema: asn1js.fromBER(body).result });
	const sent = request.tbsRequest.requestExtensions?.find(
		(e) => e.extnID === "1.3.6.1.5.5.7.48.1.2",
	);
	if (!sent) return undefined;
	const value = asn1js.fromBER(sent.extnValue.valueBlock.valueHexView).result as asn1js.OctetString;
	return new Uint8Array(value.valueBlock.valueHexView);
}

type Served =
	| Uint8Array
	| ((body: Uint8Array | undefined) => Promise<Uint8Array>)
	| "down"
	| "refused";

type Table = Record<string, Served>;

/** Sources answering from a table by URL, counting what was asked. */
function sources(table: Table, start = Date.now()) {
	const asked: string[] = [];
	let now = start;
	return {
		asked,
		at: (ms: number) => {
			now = ms;
		},
		now: () => now,
		random: (n: number) => new Uint8Array(n).fill(9),
		fetch: async (url: string, body?: Uint8Array): Promise<Fetched> => {
			asked.push(url);
			const served = table[url];
			if (!served || served === "down") return { kind: "outage" };
			if (served === "refused") return { kind: "refused" };
			return { kind: "material", body: served instanceof Uint8Array ? served : await served(body) };
		},
	};
}

/** A root, an intermediate with its CRL and OCSP locations, and a client under it with its own. */
async function chain() {
	const root = await issue({ cn: "root", ca: true });
	const intermediate = await issue({
		cn: "intermediate",
		by: root,
		ca: true,
		crl: "http://root.example/crl",
		ocsp: "http://root.example/ocsp",
	});
	const client = await issue({
		cn: "client",
		by: intermediate,
		crl: "http://ca.example/crl",
		ocsp: "http://ca.example/ocsp",
	});
	const path = [client, intermediate, root].map((issued) => issued.certificate);
	/** One check of the path (or another) under a fresh revocation over `table`. */
	const checkOnce = (table: Table, more: Partial<Policy> = {}, on = path) =>
		revocationOver(policyOf(more), sources(table)).check(on);
	return { root, intermediate, client, path, checkOnce };
}

/** An OCSP answer echoing the request's nonce. */
const answering = (spec: Omit<Answering, "nonce">) => async (body: Uint8Array | undefined) => {
	const nonce = body && nonceOf(body);
	return ocspOf({ ...spec, ...(nonce ? { nonce } : {}) });
};

describe("revocation by CRL", () => {
	it("judges a kept CRL again for each certificate, refusing it for one of another issuer", async () => {
		const root = await issue({ cn: "root", ca: true });
		const a = await issue({ cn: "a", by: root, ca: true, crl: "http://root.example/crl" });
		const b = await issue({ cn: "b", by: root, ca: true, crl: "http://root.example/crl" });
		const underA = await issue({ cn: "client", by: a, crl: "http://shared.example/crl" });
		const underB = await issue({ cn: "client", by: b, crl: "http://shared.example/crl" });
		const revocation = revocationOver(
			policyOf(),
			sources({
				"http://shared.example/crl": await crlOf({ by: a }),
				"http://root.example/crl": await crlOf({ by: root }),
			}),
		);
		const pathOf = (...issued: Issued[]) => issued.map((one) => one.certificate);
		expect(await revocation.check(pathOf(underA, a, root))).toEqual({ kind: "good" });
		expect(await revocation.check(pathOf(underB, b, root))).toEqual({
			kind: "refused",
			reason: "issuer",
		});
	});

	it("checks every certificate but the anchor, and tells revoked from good", async () => {
		const { root, intermediate, client, path, checkOnce } = await chain();
		const s = sources({
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root }),
		});
		expect(await revocationOver(policyOf(), s).check(path)).toEqual({ kind: "good" });
		expect(s.asked.sort()).toEqual(["http://ca.example/crl", "http://root.example/crl"]);
		const revoked: Table = {
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root, revoked: [intermediate] }),
		};
		expect(await checkOnce(revoked)).toEqual({ kind: "revoked" });
		const leaf: Table = {
			"http://ca.example/crl": await crlOf({ by: intermediate, revoked: [client] }),
			"http://root.example/crl": "down",
		};
		expect(await checkOnce(leaf)).toEqual({ kind: "revoked" });
	});

	it("tells an outage from a refusal, trying each location in turn", async () => {
		const { root, intermediate, checkOnce } = await chain();
		const above: Table = {
			"http://ca.example/crl": "down",
			"http://root.example/crl": await crlOf({ by: root, revoked: [intermediate] }),
		};
		expect(await checkOnce(above)).toEqual({ kind: "revoked" });
		const twice = await issue({
			cn: "client",
			by: intermediate,
			crl: "http://ca.example/crl",
			points: [pointAt("http://ca.example/second.crl")],
		});
		const second: Table = {
			"http://ca.example/crl": "down",
			"http://ca.example/second.crl": await crlOf({ by: intermediate, revoked: [twice] }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		const listed = [twice.certificate, intermediate.certificate, root.certificate];
		expect(await checkOnce(second, {}, listed)).toEqual({ kind: "revoked" });
		const down: Table = { "http://root.example/crl": await crlOf({ by: root }) };
		expect(await checkOnce(down)).toMatchObject({ kind: "outage" });
		const host: Table = {
			"http://ca.example/crl": "refused",
			"http://root.example/crl": await crlOf({ by: root }),
		};
		expect(await checkOnce(host)).toMatchObject({ kind: "refused" });
		const forged: Table = {
			"http://ca.example/crl": await crlOf({ by: intermediate, keys: await ecKeys() }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		expect(await checkOnce(forged)).toEqual({
			kind: "refused",
			reason: "signature",
		});
		// A refusal outweighs an outage, at another location of one certificate or up the path.
		const mixed: Table = {
			"http://ca.example/crl": "down",
			"http://ca.example/second.crl": await crlOf({ by: intermediate, keys: await ecKeys() }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		expect(await checkOnce(mixed, {}, listed)).toMatchObject({
			kind: "refused",
		});
		const upward: Table = {
			"http://ca.example/crl": "down",
			"http://root.example/crl": await crlOf({ by: root, keys: await ecKeys() }),
		};
		expect(await checkOnce(upward)).toMatchObject({ kind: "refused" });
		const bare = await issue({ cn: "client", by: intermediate });
		const none: Table = { "http://root.example/crl": await crlOf({ by: root }) };
		const unlisted = [bare.certificate, intermediate.certificate, root.certificate];
		expect(await checkOnce(none, {}, unlisted)).toEqual({
			kind: "refused",
			reason: "no source",
		});
	});

	it("keeps a CRL until its next update or its time to live, whichever comes first", async () => {
		const { root, intermediate, path } = await chain();
		const start = Date.now();
		const table: Table = {
			"http://ca.example/crl": await crlOf({ by: intermediate, nextUpdate: start + 600_000 }),
			"http://root.example/crl": await crlOf({ by: root, nextUpdate: start + 100_000_000 }),
		};
		const s = sources(table, start);
		const revocation = revocationOver(policyOf(), s);
		const count = (host: string) => s.asked.filter((url) => url.includes(host)).length;
		await revocation.check(path);
		await revocation.check(path);
		expect([count("ca."), count("root.")]).toEqual([1, 1]);
		table["http://ca.example/crl"] = await crlOf({
			by: intermediate,
			nextUpdate: start + 100_000_000,
		});
		s.at(start + 600_001);
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		expect([count("ca."), count("root.")]).toEqual([2, 1]);
		s.at(start + 3_600_001);
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		expect([count("ca."), count("root.")]).toEqual([2, 2]);
	});

	it("remembers a failure a while before asking again", async () => {
		const { root, intermediate, path } = await chain();
		const start = Date.now();
		const s = sources(
			{ "http://ca.example/crl": "down", "http://root.example/crl": await crlOf({ by: root }) },
			start,
		);
		const revocation = revocationOver(policyOf(), s);
		const count = () => s.asked.filter((url) => url.includes("ca.")).length;
		expect(await revocation.check(path)).toMatchObject({ kind: "outage" });
		s.at(start + 29_000);
		expect(await revocation.check(path)).toMatchObject({ kind: "outage" });
		expect(count()).toBe(1);
		s.at(start + 31_000);
		await revocation.check(path);
		expect(count()).toBe(2);
		const forged = sources(
			{
				"http://ca.example/crl": await crlOf({ by: intermediate, keys: await ecKeys() }),
				"http://root.example/crl": await crlOf({ by: root }),
			},
			start,
		);
		const refusing = revocationOver(policyOf(), forged);
		await refusing.check(path);
		forged.at(start + 29_000);
		expect(await refusing.check(path)).toMatchObject({ kind: "refused" });
		expect(forged.asked.filter((url) => url.includes("ca.")).length).toBe(1);
	});

	it("keeps no more CRLs than it may, forgetting the oldest", async () => {
		const { root, intermediate, path } = await chain();
		const s = sources({
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root }),
		});
		const revocation = revocationOver(policyOf({ crlEntries: 1 }), s);
		await revocation.check(path);
		await revocation.check(path);
		expect(s.asked.length).toBe(4);
	});
});

describe("revocation by OCSP", () => {
	it("asks with a nonce and tells good, revoked and unknown apart", async () => {
		const { root, intermediate, client, checkOnce } = await chain();
		const rootAnswer = answering({ cert: intermediate, issuer: root });
		for (const [status, kind] of [
			["good", "good"],
			["revoked", "revoked"],
			["unknown", "refused"],
		] as const) {
			const s: Table = {
				"http://ca.example/ocsp": answering({ cert: client, issuer: intermediate, status }),
				"http://root.example/ocsp": rootAnswer,
			};
			expect((await checkOnce(s, { mode: "ocsp" })).kind).toBe(kind);
		}
	});

	it("takes an answer without a nonce only when told not to ask with one", async () => {
		const { root, intermediate, client, path } = await chain();
		const table = {
			"http://ca.example/ocsp": async () => ocspOf({ cert: client, issuer: intermediate }),
			"http://root.example/ocsp": async () => ocspOf({ cert: intermediate, issuer: root }),
		};
		const asked: (Uint8Array | undefined)[] = [];
		const s = sources(table);
		const fetch = s.fetch;
		const watched = {
			...s,
			fetch: async (url: string, body?: Uint8Array) => {
				asked.push(body && nonceOf(body));
				return fetch(url, body);
			},
		};
		expect(await revocationOver(policyOf({ mode: "ocsp" }), watched).check(path)).toEqual({
			kind: "refused",
			reason: "nonce",
		});
		expect(asked[0]).toEqual(new Uint8Array(16).fill(9));
		asked.length = 0;
		expect(
			await revocationOver(policyOf({ mode: "ocsp", nonce: false }), watched).check(path),
		).toEqual({ kind: "good" });
		expect(asked).toEqual([undefined, undefined]);
	});

	it("remembers a responder that failed a while before asking it again", async () => {
		const { root, intermediate, path } = await chain();
		const start = Date.now();
		const s = sources(
			{
				"http://ca.example/ocsp": "down",
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			},
			start,
		);
		const revocation = revocationOver(policyOf({ mode: "ocsp" }), s);
		const count = () => s.asked.filter((url) => url.includes("ca.")).length;
		await revocation.check(path);
		s.at(start + 29_000);
		expect(await revocation.check(path)).toMatchObject({ kind: "outage" });
		expect(count()).toBe(1);
		s.at(start + 31_000);
		await revocation.check(path);
		expect(count()).toBe(2);
	});

	it("refuses a certificate that names no responder", async () => {
		const { root, intermediate, checkOnce } = await chain();
		const bare = await issue({ cn: "client", by: intermediate });
		const s: Table = {
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
		};
		const path = [bare, intermediate, root].map((issued) => issued.certificate);
		expect(await checkOnce(s, { mode: "ocsp" }, path)).toEqual({
			kind: "refused",
			reason: "no source",
		});
	});

	it("takes a responder's internal error or try later as an outage", async () => {
		const { root, intermediate, client, checkOnce } = await chain();
		for (const responseStatus of [2, 3]) {
			const s: Table = {
				"http://ca.example/ocsp": answering({ cert: client, issuer: intermediate, responseStatus }),
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			};
			expect(await checkOnce(s, { mode: "ocsp" })).toEqual({
				kind: "outage",
				reason: "busy",
			});
		}
	});

	it("never lets a responder that is down outweigh one whose answer refuses, in either order", async () => {
		const { root, intermediate, checkOnce } = await chain();
		const second = new pkijs.AccessDescription({
			accessMethod: "1.3.6.1.5.5.7.48.1",
			accessLocation: new pkijs.GeneralName({ type: 6, value: "http://second.example/ocsp" }),
		});
		const client = await issue({
			cn: "client",
			by: intermediate,
			ocsp: "http://ca.example/ocsp",
			access: [second],
		});
		const path = [client, intermediate, root].map((issued) => issued.certificate);
		const busy = answering({ cert: client, issuer: intermediate, responseStatus: 3 });
		const forged = answering({ cert: client, issuer: intermediate, keys: await ecKeys() });
		for (const [first, then] of [
			[busy, forged],
			[forged, busy],
		]) {
			const s: Table = {
				"http://ca.example/ocsp": first as Served,
				"http://second.example/ocsp": then as Served,
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			};
			expect(await checkOnce(s, { mode: "ocsp" }, path)).toEqual({
				kind: "refused",
				reason: "signature",
			});
		}
	});

	it("keeps an answer for the issuer it is about, by name as well as key", async () => {
		const keys = await ecKeys();
		const [a, b] = [
			await issue({ cn: "issuer-a", ca: true, keys }),
			await issue({ cn: "issuer-b", ca: true, keys }),
		];
		const underA = await issue({ cn: "client", by: a, serial: 500, ocsp: "http://a.example/ocsp" });
		const underB = await issue({ cn: "client", by: b, serial: 500, ocsp: "http://b.example/ocsp" });
		const s = sources({
			"http://a.example/ocsp": answering({ cert: underA, issuer: a }),
			"http://b.example/ocsp": answering({ cert: underB, issuer: b, status: "revoked" }),
		});
		const revocation = revocationOver(policyOf({ mode: "ocsp" }), s);
		expect(await revocation.check([underA.certificate, a.certificate])).toEqual({ kind: "good" });
		expect(await revocation.check([underB.certificate, b.certificate])).toEqual({
			kind: "revoked",
		});
		// Nor for another issuer of the same name, nor for another certificate of the same issuer.
		const twin = await issue({ cn: "issuer-a", ca: true });
		const underTwin = await issue({
			cn: "client",
			by: twin,
			serial: 500,
			ocsp: "http://t.example/ocsp",
		});
		const other = await issue({ cn: "client", by: a, serial: 501, ocsp: "http://o.example/ocsp" });
		const more = sources({
			"http://a.example/ocsp": answering({ cert: underA, issuer: a }),
			"http://t.example/ocsp": answering({ cert: underTwin, issuer: twin, status: "revoked" }),
			"http://o.example/ocsp": answering({ cert: other, issuer: a, status: "revoked" }),
		});
		const kept = revocationOver(policyOf({ mode: "ocsp" }), more);
		expect(await kept.check([underA.certificate, a.certificate])).toEqual({ kind: "good" });
		expect(await kept.check([underTwin.certificate, twin.certificate])).toEqual({
			kind: "revoked",
		});
		expect(await kept.check([other.certificate, a.certificate])).toEqual({ kind: "revoked" });
	});

	it("keeps an answer until it ends, and asks again after", async () => {
		const { root, intermediate, client, path } = await chain();
		const start = Date.now();
		const s = sources(
			{
				"http://ca.example/ocsp": answering({
					cert: client,
					issuer: intermediate,
					nextUpdate: start + 600_000,
				}),
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			},
			start,
		);
		const revocation = revocationOver(policyOf({ mode: "ocsp" }), s);
		await revocation.check(path);
		await revocation.check(path);
		expect(s.asked.length).toBe(2);
		s.at(start + 600_000 + 1);
		await revocation.check(path);
		expect(s.asked.filter((url) => url.startsWith("http://ca")).length).toBe(2);
	});

	it("keeps an answer no longer than its delegated responder is in date", async () => {
		const { root, intermediate, client, path } = await chain();
		const start = Date.now();
		const ends = Math.floor((start + 600_000) / 1000) * 1000;
		const free = await issue({
			cn: "free",
			by: intermediate,
			eku: [ocspSigning],
			noCheck: true,
			notAfter: ends,
		});
		const s = sources(
			{
				"http://ca.example/ocsp": answering({
					cert: client,
					issuer: intermediate,
					by: free,
					certs: [free],
					nextUpdate: start + 3_600_000,
				}),
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			},
			start,
		);
		const revocation = revocationOver(policyOf({ mode: "ocsp" }), s);
		const count = () => s.asked.filter((url) => url.startsWith("http://ca")).length;
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		s.at(ends - 1);
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		expect(count()).toBe(1);
		// At its end it is asked again, and taken while the responder is still in date.
		s.at(ends);
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		expect(count()).toBe(2);
		s.at(ends + 1);
		expect(await revocation.check(path)).toEqual({ kind: "refused", reason: "signer" });
		expect(count()).toBe(3);
	});

	it("takes a delegated responder only where its own revocation can be checked", async () => {
		const { root, intermediate, client, checkOnce } = await chain();
		const delegated = await issue({
			cn: "responder",
			by: intermediate,
			eku: [ocspSigning],
			crl: "http://ca.example/crl",
		});
		const free = await issue({ cn: "free", by: intermediate, eku: [ocspSigning], noCheck: true });
		const by = async (responder: Issued): Promise<Table> => ({
			"http://ca.example/ocsp": answering({
				cert: client,
				issuer: intermediate,
				by: responder,
				certs: [responder],
			}),
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			"http://root.example/crl": await crlOf({ by: root }),
		});
		const ocsp = { mode: "ocsp" } as const;
		expect(await checkOnce(await by(delegated), ocsp)).toEqual({
			kind: "refused",
			reason: "responder",
		});
		expect(await checkOnce(await by(free), ocsp)).toEqual({
			kind: "good",
		});
		// One that needs no check is still held to the key rules of the path.
		const small = await issue({
			cn: "small",
			by: intermediate,
			eku: [ocspSigning],
			noCheck: true,
			keys: await rsaKeys(1024),
		});
		expect(await checkOnce(await by(small), ocsp)).toEqual({
			kind: "refused",
			reason: "signer",
		});
		// Under OCSP alone, no CRL is asked for, even where the responder names one.
		const named = {
			...(await by(delegated)),
			"http://ca.example/crl": await crlOf({ by: intermediate }),
		};
		expect(await checkOnce(named, ocsp)).toMatchObject({
			kind: "refused",
		});
		const both = { mode: "both" } as const;
		const checked = {
			...(await by(delegated)),
			"http://ca.example/crl": await crlOf({ by: intermediate }),
		};
		expect(await checkOnce(checked, both)).toEqual({ kind: "good" });
		// A revoked responder's answer is dropped, and the CRL decides.
		const revoked = {
			...(await by(delegated)),
			"http://ca.example/crl": await crlOf({ by: intermediate, revoked: [delegated, client] }),
		};
		expect(await checkOnce(revoked, both)).toEqual({ kind: "revoked" });
		// A responder that answers revoked or unknown refuses, whether or not it can be checked.
		for (const [status, said] of [
			["revoked", { kind: "revoked" }],
			["unknown", { kind: "refused", reason: "unknown" }],
		] as const) {
			const table: Table = {
				"http://ca.example/ocsp": answering({
					cert: client,
					issuer: intermediate,
					by: delegated,
					certs: [delegated],
					status,
				}),
				"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
				"http://root.example/crl": await crlOf({ by: root }),
				"http://ca.example/crl": "down",
			};
			expect(await checkOnce(table, both), status).toEqual(said);
		}
		// A responder whose own revocation cannot be fetched is an outage, not a refusal.
		const unreachable: Table = { ...(await by(delegated)), "http://ca.example/crl": "down" };
		expect(await checkOnce(unreachable, both)).toMatchObject({
			kind: "outage",
		});
	});
});

describe("revocation by both", () => {
	it("asks OCSP first, falls back to the CRL, and lets the CRL only add a revocation to unknown", async () => {
		const { root, intermediate, client, path, checkOnce } = await chain();
		const rest = {
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		const good = answering({ cert: client, issuer: intermediate });
		const unknown = answering({ cert: client, issuer: intermediate, status: "unknown" });
		const forged = answering({ cert: client, issuer: intermediate, keys: await ecKeys() });
		const listing = await crlOf({ by: intermediate, revoked: [client] });
		const empty = await crlOf({ by: intermediate });
		// The client's OCSP answer and CRL, and what the check says.
		const cases: [string, Served, Served, unknown][] = [
			["good stands over a CRL listing it", good, listing, { kind: "good" }],
			["down falls back to the CRL", "down", listing, { kind: "revoked" }],
			["the CRL adds a revocation to unknown", unknown, listing, { kind: "revoked" }],
			[
				"unknown stands when the CRL lists nothing",
				unknown,
				empty,
				{ kind: "refused", reason: "unknown" },
			],
			["a forged answer yields to the CRL", forged, empty, { kind: "good" }],
			[
				"a forged answer and no CRL refuse",
				forged,
				"down",
				{ kind: "refused", reason: "signature" },
			],
			["both down is an outage", "down", "down", { kind: "outage", reason: "unreachable" }],
		];
		for (const [name, ocsp, crl, said] of cases) {
			const table: Table = {
				...rest,
				"http://ca.example/ocsp": ocsp,
				"http://ca.example/crl": crl,
			};
			expect(await checkOnce(table, { mode: "both" }), name).toEqual(said);
		}
		// A good answer is taken without asking for the CRL.
		const first = sources({
			...rest,
			"http://ca.example/ocsp": good,
			"http://ca.example/crl": listing,
		});
		await revocationOver(policyOf({ mode: "both" }), first).check(path);
		expect(first.asked).not.toContain("http://ca.example/crl");
	});

	it("reads a responder that is down as an outage the CRL may settle, and unknown as a refusal it may only revoke", async () => {
		const { root, intermediate, client, checkOnce } = await chain();
		const rest = {
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		const busy = answering({ cert: client, issuer: intermediate, responseStatus: 2 });
		const unknown = answering({ cert: client, issuer: intermediate, status: "unknown" });
		const cases: [Served, Served, unknown][] = [
			[busy, await crlOf({ by: intermediate }), { kind: "good" }],
			[busy, "down", { kind: "outage", reason: "busy" }],
			[busy, "refused", { kind: "refused", reason: "source refused" }],
			[unknown, "down", { kind: "refused", reason: "unknown" }],
		];
		for (const [ocsp, crl, said] of cases) {
			const s: Table = { ...rest, "http://ca.example/ocsp": ocsp, "http://ca.example/crl": crl };
			expect(await checkOnce(s, { mode: "both" })).toEqual(said);
		}
	});
});

/** A gate a source waits at until it is opened. */
function gate() {
	let open = () => {};
	const shut = new Promise<void>((resolve) => {
		open = resolve;
	});
	return { open, shut };
}
const settle = () => new Promise((resolve) => setTimeout(resolve, 100));

describe("checks under way together", () => {
	it("ask a responder once, and all take what that one ask found", async () => {
		const { root, intermediate, client, path } = await chain();
		const s = sources({
			"http://ca.example/ocsp": answering({
				cert: client,
				issuer: intermediate,
				status: "revoked",
			}),
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
		});
		// The first ask is held, then fails; any later one would be answered revoked.
		const held = gate();
		let first = true;
		const gated = {
			...s,
			fetch: async (url: string, body?: Uint8Array): Promise<Fetched> => {
				if (url !== "http://ca.example/ocsp" || !first) return s.fetch(url, body);
				first = false;
				s.asked.push(url);
				await held.shut;
				return { kind: "outage" };
			},
		};
		const revocation = revocationOver(policyOf({ mode: "ocsp" }), gated);
		const together = Promise.all([revocation.check(path), revocation.check(path)]);
		await settle();
		held.open();
		const down = { kind: "outage", reason: "unreachable" };
		expect(await together).toEqual([down, down]);
		expect(s.asked.filter((url) => url === "http://ca.example/ocsp")).toHaveLength(1);
		expect(await revocation.check(path)).toEqual(down);
	});

	it("fetch a CRL once", async () => {
		const { root, intermediate, path } = await chain();
		const held = gate();
		const crl = await crlOf({ by: intermediate });
		const s = sources({
			"http://ca.example/crl": async () => {
				await held.shut;
				return crl;
			},
			"http://root.example/crl": await crlOf({ by: root }),
		});
		const revocation = revocationOver(policyOf(), s);
		const together = Promise.all([revocation.check(path), revocation.check(path)]);
		await settle();
		held.open();
		expect(await together).toEqual([{ kind: "good" }, { kind: "good" }]);
		expect(s.asked.filter((url) => url === "http://ca.example/crl")).toHaveLength(1);
	});
});

describe("the fetches one check may make", () => {
	it("leaves unconfirmed what it could not fetch within the limit, counting neither kept answers nor remembered failures", async () => {
		const { root, intermediate, path } = await chain();
		const s = sources({
			"http://ca.example/crl": await crlOf({ by: intermediate }),
			"http://root.example/crl": await crlOf({ by: root }),
		});
		const revocation = revocationOver(policyOf({ maxFetches: 1 }), s);
		expect(await revocation.check(path)).toEqual({ kind: "outage", reason: "fetch limit" });
		expect(s.asked).toEqual(["http://ca.example/crl"]);
		// The leaf's CRL is kept; the one not fetched was not remembered as failing.
		expect(await revocation.check(path)).toEqual({ kind: "good" });
		expect(s.asked).toEqual(["http://ca.example/crl", "http://root.example/crl"]);
		const down = sources({
			"http://ca.example/crl": "down",
			"http://root.example/crl": await crlOf({ by: root }),
		});
		const remembering = revocationOver(policyOf({ maxFetches: 1 }), down);
		await remembering.check(path);
		expect(await remembering.check(path)).toEqual({ kind: "outage", reason: "unreachable" });
		expect(down.asked).toEqual(["http://ca.example/crl", "http://root.example/crl"]);
	});

	it("keeps a refusal it settled before the limit cut the rest short", async () => {
		const { root, intermediate } = await chain();
		const second = new pkijs.AccessDescription({
			accessMethod: "1.3.6.1.5.5.7.48.1",
			accessLocation: new pkijs.GeneralName({ type: 6, value: "http://ca.example/second" }),
		});
		const twice = await issue({
			cn: "client",
			by: intermediate,
			ocsp: "http://ca.example/ocsp",
			access: [second],
		});
		const s = sources({
			"http://ca.example/ocsp": "refused",
			"http://ca.example/second": answering({ cert: twice, issuer: intermediate }),
		});
		const path = [twice, intermediate, root].map((issued) => issued.certificate);
		expect(await revocationOver(policyOf({ mode: "ocsp", maxFetches: 1 }), s).check(path)).toEqual({
			kind: "refused",
			reason: "source refused",
		});
		expect(s.asked).toEqual(["http://ca.example/ocsp"]);
	});

	it("counts OCSP requests too, and still finds a revocation first", async () => {
		const { root, intermediate, client, checkOnce } = await chain();
		const s: Table = {
			"http://ca.example/ocsp": answering({ cert: client, issuer: intermediate }),
			"http://root.example/ocsp": answering({ cert: intermediate, issuer: root }),
		};
		expect(await checkOnce(s, { mode: "ocsp", maxFetches: 1 })).toEqual({
			kind: "outage",
			reason: "fetch limit",
		});
		const revoked: Table = {
			"http://ca.example/crl": await crlOf({ by: intermediate, revoked: [client] }),
			"http://root.example/crl": await crlOf({ by: root }),
		};
		expect(await checkOnce(revoked, { maxFetches: 1 })).toEqual({ kind: "revoked" });
	});
});

describe("a revocation, which only a hold lifts", () => {
	const hold = 6;
	const held = new pkijs.Extension({
		extnID: "2.5.29.21",
		extnValue: new asn1js.Enumerated({ value: hold }).toBER(false),
	});

	/** Revoked by its CRL or OCSP answer, which ends in a minute; then asked again two hours on with that source down. */
	async function revokedThenDown(mode: "crl" | "ocsp", reason?: number) {
		const { root, intermediate, client, path } = await chain();
		const soon = Date.now() + 60_000;
		const later = Date.now() + 86_400_000;
		const table: Table = {
			"http://ca.example/crl": await crlOf({
				by: intermediate,
				revoked: [client],
				nextUpdate: soon,
				...(reason === undefined ? {} : { entryExtensions: [held] }),
			}),
			"http://root.example/crl": await crlOf({ by: root, nextUpdate: later }),
			"http://ca.example/ocsp": answering({
				cert: client,
				issuer: intermediate,
				status: "revoked",
				nextUpdate: soon,
				...(reason === undefined ? {} : { reason }),
			}),
			"http://root.example/ocsp": answering({
				cert: intermediate,
				issuer: root,
				nextUpdate: later,
			}),
		};
		const s = sources(table);
		const revocation = revocationOver(policyOf({ mode }), s);
		const first = await revocation.check(path);
		table[`http://ca.example/${mode}`] = "down";
		s.at(Date.now() + 7_200_000);
		return { first, again: await revocation.check(path) };
	}

	it("keeps refusing a certificate a CRL revoked after the CRL ends and its source is down", async () => {
		const { first, again } = await revokedThenDown("crl");
		expect([first.kind, again.kind]).toEqual(["revoked", "revoked"]);
	});

	it("keeps refusing a certificate an OCSP answer revoked after the answer ends and its responder is down", async () => {
		const { first, again } = await revokedThenDown("ocsp");
		expect([first.kind, again.kind]).toEqual(["revoked", "revoked"]);
	});

	it("keeps refusing for any other reason given, key compromise among them", async () => {
		const { first, again } = await revokedThenDown("ocsp", 1);
		expect([first.kind, again.kind]).toEqual(["revoked", "revoked"]);
	});

	it("asks again about a certificate on hold, once what said so ends", async () => {
		for (const mode of ["crl", "ocsp"] as const) {
			const { first, again } = await revokedThenDown(mode, hold);
			expect([first.kind, again.kind], mode).toEqual(["revoked", "outage"]);
		}
	});
});
