import { crlOf, type Issued, issue, pemOf } from "@mod/x509-path/testing";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { describe, expect, it } from "vitest";
import { type Fetched, revocationOver, storeTrust } from "../revocation.ts";

const serverAuth = "1.3.6.1.5.5.7.3.1";
const atRoot = "http://crl.example/root.crl";
const numbered = (n: number) =>
	new pkijs.Extension({
		extnID: "2.5.29.20",
		extnValue: new asn1js.Integer({ value: n }).toBER(false),
	});
const onHold = new pkijs.Extension({
	extnID: "2.5.29.21",
	extnValue: new asn1js.Enumerated({ value: 6 }).toBER(false),
});

type Serving = Uint8Array | Fetched | ((signal: AbortSignal) => Promise<Fetched>);

/** A check over `root` alone, its CRLs fetched from a table by URL at a clock the test moves. */
function checking(
	root: Issued,
	table: Record<string, Serving>,
	hosts = ["crl.example"],
	atOnce = false,
) {
	let now = Date.now();
	const fetched: string[] = [];
	const running: Promise<unknown>[] = [];
	const background: ((signal: AbortSignal) => Promise<unknown>)[] = [];
	const revocation = revocationOver({
		trust: storeTrust(pemOf(root.der)),
		hosts,
		crlEntries: 8,
		fetching: {
			fetch: async (url, signal) => {
				fetched.push(url);
				const serving = table[url] ?? "unreachable";
				return typeof serving === "function" ? serving(signal) : serving;
			},
			inBackground: (refresh) => {
				background.push(refresh);
				if (atOnce) running.push(refresh(new AbortController().signal));
			},
			now: () => now,
			failureMs: 30_000,
			crlTtlMs: 3_600_000,
		},
	});
	const check = (leaf: Issued, sent: Issued[] = [], signal = new AbortController().signal) =>
		revocation.check(
			leaf.der,
			sent.map((one) => one.der),
			signal,
		);
	const settled = () => Promise.all(running);
	return { check, fetched, background, settled, table, later: (ms: number) => (now += ms) };
}

const leafOf = (by: Issued, more = {}) =>
	issue({ cn: "peer.example", by, eku: [serverAuth], crl: atRoot, ...more });

describe("a peer's revocation", () => {
	it("is good with no CRL to ask, and revoked where its issuer's CRL lists it or the intermediate above", async () => {
		const root = await issue({ cn: "root", ca: true });
		const unnamed = await issue({ cn: "peer.example", by: root, eku: [serverAuth] });
		const leaf = await leafOf(root);
		const listed = await leafOf(root);
		const s = checking(root, { [atRoot]: await crlOf({ by: root, revoked: [listed] }) });
		expect(await s.check(unnamed)).toEqual({ kind: "good" });
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		expect(await s.check(listed)).toEqual({ kind: "revoked" });
		const mid = await issue({ cn: "mid", by: root, ca: true, crl: atRoot });
		const under = await issue({ cn: "peer.example", by: mid, eku: [serverAuth] });
		const above = checking(root, { [atRoot]: await crlOf({ by: root, revoked: [mid] }) });
		expect(await above.check(under, [mid])).toEqual({ kind: "revoked" });
	});

	it("is unconfirmed where no point will do, a path its rules refuse, or a fetch failed, and says why", async () => {
		const root = await issue({ cn: "root", ca: true });
		const https = await leafOf(root, { crl: "https://crl.example/root.crl" });
		const unlisted = await leafOf(root, { crl: "http://elsewhere.example/root.crl" });
		const scoped = await leafOf(root, { crl: "ldap://crl.example/root" });
		const forClients = await issue({
			cn: "peer.example",
			by: root,
			eku: ["1.3.6.1.5.5.7.3.2"],
			crl: atRoot,
		});
		const s = checking(root, { [atRoot]: "refused" });
		const reason = async (leaf: Issued) => {
			const verdict = await s.check(leaf);
			return verdict.kind === "unconfirmed" ? verdict.reason : verdict.kind;
		};
		expect(await reason(https)).toBe("https-only");
		expect(await reason(unlisted)).toBe("unlisted");
		expect(await reason(scoped)).toBe("unsupported");
		expect(await reason(forClients)).toBe("path");
		expect(await reason(await leafOf(root))).toBe("refused");
		expect(s.fetched).toEqual([atRoot]);
	});

	it("tells a CRL its issuer could not have signed, as one without the right to sign CRLs, apart from one signed otherwise", async () => {
		// Key usage for signing certificates alone: no cRLSign.
		const root = await issue({ cn: "root", ca: true, keyUsage: 0x04 });
		const leaf = await leafOf(root);
		const other = await issue({ cn: "root", ca: true });
		const s = checking(root, { [atRoot]: await crlOf({ by: root }) });
		expect(await s.check(leaf)).toEqual({ kind: "unconfirmed", reason: "issuer" });
		const signedOtherwise = await issue({ cn: "root", ca: true });
		const t = checking(signedOtherwise, {
			[atRoot]: await crlOf({ by: signedOtherwise, keys: other.keys }),
		});
		expect(await t.check(await leafOf(signedOtherwise))).toEqual({
			kind: "unconfirmed",
			reason: "signature",
		});
	});

	it("keys no issuer by a name past 4 KiB, nor fetches from a URL past 2 KiB: both unconfirmed, never passed", async () => {
		const root = await issue({ cn: "root", ca: true });
		const long = await leafOf(root, { crl: `http://crl.example/${"a".repeat(2100)}` });
		const s = checking(root, { [atRoot]: await crlOf({ by: root }) });
		expect(await s.check(long)).toEqual({ kind: "unconfirmed", reason: "unsupported" });
		const named = await issue({ cn: "n".repeat(5000), ca: true });
		const under = await leafOf(named);
		const t = checking(named, { [atRoot]: await crlOf({ by: named }) });
		expect(await t.check(under)).toEqual({ kind: "unconfirmed", reason: "malformed" });
		expect([s.fetched, t.fetched]).toEqual([[], []]);
	});

	it("finds an anchor without key identifiers whose name is written in another string type", async () => {
		const root = await issue({ cn: "root", ca: true, printableSubject: true });
		const mid = await issue({ cn: "mid", by: root, ca: true });
		const leaf = await issue({ cn: "peer.example", by: mid, eku: [serverAuth] });
		expect(await checking(root, {}).check(leaf, [mid])).toEqual({ kind: "good" });
	});
});

describe("keeping what CRLs said", () => {
	it("keeps a revocation other than a hold after a later CRL leaves it out, and asks again of a hold", async () => {
		const root = await issue({ cn: "root", ca: true });
		const [revoked, held] = await Promise.all([leafOf(root), leafOf(root)]);
		const s = checking(root, {
			[atRoot]: await crlOf({ by: root, revoked: [revoked], extensions: [numbered(1)] }),
		});
		expect(await s.check(revoked)).toEqual({ kind: "revoked" });
		/** The CRL numbered `n`, `hours` on: in force once the clock has moved so far. */
		const later = (n: number, hours: number, listed: Issued[], more = {}) =>
			crlOf({
				by: root,
				revoked: listed,
				extensions: [numbered(n)],
				thisUpdate: Date.now() + hours * 3_600_000 - 60_000,
				nextUpdate: Date.now() + (hours + 1) * 3_600_000,
				...more,
			});
		s.table[atRoot] = await later(2, 2, [held], { entryExtensions: [onHold] });
		s.later(2 * 3_600_000);
		expect(await s.check(held)).toEqual({ kind: "revoked" });
		s.table[atRoot] = await later(3, 4, []);
		s.later(2 * 3_600_000);
		// Left out of the newer CRLs, the revocation stands; the hold is asked again.
		expect(await s.check(revoked)).toEqual({ kind: "revoked" });
		expect(await s.check(held)).toEqual({ kind: "good" });
	});

	it("takes no older CRL after a newer, answering by the one kept until its next update", async () => {
		const root = await issue({ cn: "root", ca: true });
		const leaf = await leafOf(root);
		const s = checking(root, { [atRoot]: await crlOf({ by: root, extensions: [numbered(5)] }) });
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		s.later(2 * 3_600_000);
		const at = (n: number) =>
			crlOf({
				by: root,
				extensions: [numbered(n)],
				thisUpdate: Date.now() + 2 * 3_600_000 - 60_000,
				nextUpdate: Date.now() + 3 * 3_600_000,
			});
		s.table[atRoot] = await at(4);
		expect(await s.check(leaf)).toEqual({ kind: "unconfirmed", reason: "rollback" });
		s.later(31_000);
		s.table[atRoot] = await at(6);
		expect(await s.check(leaf)).toEqual({ kind: "good" });
	});
});

describe("fetching a CRL", () => {
	it("fetches once for the checks waiting together, and remembers a failure for its lifetime", async () => {
		const root = await issue({ cn: "root", ca: true });
		const leaf = await leafOf(root);
		const s = checking(root, { [atRoot]: "unreachable" });
		expect(await Promise.all([s.check(leaf), s.check(leaf), s.check(leaf)])).toEqual(
			Array(3).fill({ kind: "unconfirmed", reason: "unreachable" }),
		);
		expect(await s.check(leaf)).toEqual({ kind: "unconfirmed", reason: "unreachable" });
		expect(s.fetched).toHaveLength(1);
		s.later(31_000);
		s.table[atRoot] = await crlOf({ by: root });
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		expect(s.fetched).toHaveLength(2);
	});

	it("remembers nothing of a fetch cut short by the check that started it, and one waiting fetches again", async () => {
		const root = await issue({ cn: "root", ca: true });
		const leaf = await leafOf(root);
		const crl = await crlOf({ by: root });
		let first = true;
		const s = checking(root, {
			[atRoot]: (signal) => {
				if (!first) return Promise.resolve(crl);
				first = false;
				return new Promise((ended) => signal.addEventListener("abort", () => ended("aborted")));
			},
		});
		const starting = new AbortController();
		const started = s.check(leaf, [], starting.signal);
		// The first check's fetch is under way before the other waits on it, and before it ends.
		while (s.fetched.length === 0) await new Promise((tick) => setTimeout(tick, 1));
		const waiting = s.check(leaf);
		await new Promise((tick) => setTimeout(tick, 5));
		starting.abort();
		expect(await started).toEqual({ kind: "unconfirmed", reason: "unreachable" });
		expect(await waiting).toEqual({ kind: "good" });
		expect(s.fetched).toHaveLength(2);
	});

	it("holds a refresh back by a failure remembered, as a fetch is held", async () => {
		const root = await issue({ cn: "root", ca: true });
		const leaf = await leafOf(root);
		const s = checking(
			root,
			{ [atRoot]: await crlOf({ by: root, nextUpdate: Date.now() + 86_400_000 }) },
			["crl.example"],
			true,
		);
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		s.later(3_600_001);
		s.table[atRoot] = "unreachable";
		for (let n = 0; n < 5; n++) {
			expect(await s.check(leaf)).toEqual({ kind: "good" });
			await s.settled();
		}
		// The first refresh failed; the four after it waited on the failure's lifetime.
		expect(s.fetched).toHaveLength(2);
		s.later(31_000);
		await s.check(leaf);
		await s.settled();
		expect(s.fetched).toHaveLength(3);
	});

	it("fetches again in the background after crl-ttl, the one kept answering meanwhile", async () => {
		const root = await issue({ cn: "root", ca: true });
		const leaf = await leafOf(root);
		const s = checking(root, {
			[atRoot]: await crlOf({ by: root, nextUpdate: Date.now() + 86_400_000 }),
		});
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		s.later(3_600_001);
		s.table[atRoot] = await crlOf({
			by: root,
			revoked: [leaf],
			nextUpdate: Date.now() + 86_400_000,
		});
		expect(await s.check(leaf)).toEqual({ kind: "good" });
		expect(s.background).toHaveLength(1);
		await s.background[0]?.(new AbortController().signal);
		expect(await s.check(leaf)).toEqual({ kind: "revoked" });
	});
});

describe("a check's cost, its CRL kept", () => {
	it("checks a peer under one intermediate, each CRL kept, within a bound, and logs how long", async () => {
		const root = await issue({ cn: "root", ca: true });
		const mid = await issue({ cn: "mid", by: root, ca: true, crl: atRoot });
		const atMid = "http://crl.example/mid.crl";
		const leaf = await issue({ cn: "peer.example", by: mid, eku: [serverAuth], crl: atMid });
		const s = checking(root, {
			[atRoot]: await crlOf({ by: root }),
			[atMid]: await crlOf({ by: mid }),
		});
		expect(await s.check(leaf, [mid])).toEqual({ kind: "good" });
		const runs = 50;
		const started = performance.now();
		for (let run = 0; run < runs; run++) await s.check(leaf, [mid]);
		const ms = (performance.now() - started) / runs;
		console.log(JSON.stringify({ keptCheckMs: ms }));
		expect(s.fetched).toHaveLength(2);
		expect(ms).toBeLessThan(250);
	});
});
