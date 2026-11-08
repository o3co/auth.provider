import { X509Certificate } from "node:crypto";
import { getCACertificates } from "node:tls";
import { describe, expect, it } from "vitest";
import { type Issued, issue } from "../../testing.ts";
import { chosen, trustOf } from "../choice.ts";

/** What a choice gives, as its kind and the CNs of the chain chosen, by their DER. */
const pickOf = (leaf: Issued, sent: readonly Issued[], anchors: readonly Issued[], depth = 4) => {
	const trust = trustOf({ anchors: anchors.map((a) => a.der), selfSignedAnchorsOnly: false });
	const picked = chosen(
		leaf.der,
		sent.map((s) => s.der),
		trust,
		depth,
	);
	if (picked.kind !== "chain") return picked.kind;
	return picked.chain
		.map((der) => new X509Certificate(der).subject.replace(/^CN=/, ""))
		.join(" > ");
};
/** One signed as `cn` by keys whose issuer is named `issuerCn`, as a peer could make them. */
const signedBy = (cn: string, issuerCn: string, by: Issued, more = {}) =>
	issue({ cn, by: { ...by, cn: issuerCn }, ca: true, ...more });

describe("choosing a path", () => {
	it("takes no edge node does not read as issued, though its key identifier and signature match: a self-issued one named apart", async () => {
		const root = await issue({ cn: "B", ca: true, keyIds: true });
		// Subject and issuer "A", its key identifier B's, signed by B: node's checkIssued says no.
		const posing = await issue({ cn: "A", issuerName: "A", by: root, ca: true, keyIds: true });
		const leaf = await issue({ cn: "leaf", by: posing, keyIds: true });
		expect(pickOf(leaf, [posing], [root])).toBe("path");
		const named = await issue({ cn: "A", by: root, ca: true, keyIds: true });
		const under = await issue({ cn: "leaf", by: named, keyIds: true });
		expect(pickOf(under, [named], [root])).toBe("leaf > A > B");
	});

	it("ends on a cycle of two issuers with no anchor, and takes the root a cycle also reaches", async () => {
		const root = await issue({ cn: "R", ca: true });
		const y = await issue({ cn: "Y", ca: true });
		const x = await signedBy("X", "Y", y);
		const yByX = await signedBy("Y", "X", { ...x, keys: x.keys });
		const leaf = await issue({ cn: "leaf", by: x });
		const started = performance.now();
		expect(pickOf(leaf, [x, yByX], [root])).toBe("path");
		expect(performance.now() - started).toBeLessThan(1000);
		const yByRoot = await signedBy("Y", "R", root, { keys: y.keys });
		expect(pickOf(leaf, [x, yByX, yByRoot], [root])).toBe("leaf > X > Y > R");
	});

	it("takes no certificate with more than four issuers, nor more than ten sent", async () => {
		const root = await issue({ cn: "R", ca: true });
		const first = await issue({ cn: "I", by: root, ca: true });
		const leaf = await issue({ cn: "leaf", by: first });
		// The same issuer, name and key, issued again: each an edge.
		const again = (n: number) =>
			Promise.all(
				Array.from({ length: n }, () => issue({ cn: "I", by: root, ca: true, keys: first.keys })),
			);
		expect(pickOf(leaf, [first, ...(await again(3))], [root])).toBe("leaf > I > R");
		expect(pickOf(leaf, [first, ...(await again(4))], [root])).toBe("path");
		const padding = await Promise.all(Array.from({ length: 10 }, (_, n) => issue({ cn: `p${n}` })));
		expect(pickOf(leaf, [first, ...padding], [root])).toBe("path");
	});

	it("goes on past an intermediate the trust holds to its root, and tells a path past the intermediates allowed", async () => {
		const root = await issue({ cn: "R", ca: true });
		const held = await issue({ cn: "I", by: root, ca: true });
		const leaf = await issue({ cn: "leaf", by: held });
		const trust = trustOf({
			anchors: [root.der],
			intermediates: [held.der],
			selfSignedAnchorsOnly: true,
		});
		const picked = chosen(leaf.der, [], trust, 4);
		expect(picked.kind === "chain" && picked.chain.length).toBe(3);
		expect(chosen(leaf.der, [], trust, 0)).toEqual({ kind: "too many intermediates" });
	});

	it("refuses, asked for self-signed anchors alone, one that is not", async () => {
		const root = await issue({ cn: "R", ca: true });
		const held = await issue({ cn: "I", by: root, ca: true });
		expect(() => trustOf({ anchors: [held.der], selfSignedAnchorsOnly: true })).toThrow(TypeError);
		expect(() => trustOf({ anchors: [held.der], selfSignedAnchorsOnly: false })).not.toThrow();
		expect(() =>
			trustOf({ anchors: [new Uint8Array([1, 2])], selfSignedAnchorsOnly: false }),
		).toThrow(TypeError);
	});
});

describe("a choice's cost, against the platform's store and one root more", () => {
	it("chooses an ordinary chain, a full budget and a cycle each within a bound, and logs how long", async () => {
		const extra = await issue({ cn: "extra root", ca: true });
		const store = getCACertificates("default").map((pem) => new X509Certificate(pem));
		const selfSigned = store.filter((c) => c.checkIssued(c) && c.verify(c.publicKey));
		const trust = trustOf({
			anchors: [...selfSigned.map((c) => new Uint8Array(c.raw)), extra.der],
			intermediates: store.filter((c) => !selfSigned.includes(c)).map((c) => new Uint8Array(c.raw)),
			selfSignedAnchorsOnly: true,
		});
		const timed = (leaf: Issued, sent: readonly Issued[]) => {
			const runs = 20;
			const started = performance.now();
			for (let run = 0; run < runs; run++)
				chosen(
					leaf.der,
					sent.map((s) => s.der),
					trust,
					6,
				);
			return (performance.now() - started) / runs;
		};
		// Ordinary: a leaf under two intermediates under the root.
		const a = await issue({ cn: "a", by: extra, ca: true });
		const b = await issue({ cn: "b", by: a, ca: true });
		const leaf = await issue({ cn: "leaf", by: b });
		const ordinary = timed(leaf, [b, a]);
		// Full: four issuers at each step, no anchor reached, ten sent.
		const top = await issue({ cn: "top", ca: true });
		const levels = [
			await Promise.all(
				Array.from({ length: 4 }, () => issue({ cn: "m", by: top, ca: true, keys: top.keys })),
			),
		];
		const wide = levels[0] as Issued[];
		const under = await issue({ cn: "leaf", by: wide[0] as Issued });
		const sentWide = [
			...wide,
			...(await Promise.all(Array.from({ length: 6 }, (_, n) => issue({ cn: `w${n}`, ca: true })))),
		];
		const full = timed(under, sentWide);
		// A cycle of two.
		const y = await issue({ cn: "Y", ca: true });
		const x = await signedBy("X", "Y", y);
		const yByX = await signedBy("Y", "X", { ...x, keys: x.keys });
		const cycled = await issue({ cn: "leaf", by: x });
		const cycle = timed(cycled, [x, yByX]);
		console.log(JSON.stringify({ store: store.length, ordinary, full, cycle }));
		for (const ms of [ordinary, full, cycle]) expect(ms).toBeLessThan(250);
	});
});
