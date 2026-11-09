import { X509Certificate } from "node:crypto";
import { describe, expect, it } from "vitest";
import { type Issued, issue } from "../../test/authority.ts";
import { chosen } from "../choice.ts";

/** What a choice gives, as its kind and the CNs of the chain chosen, by their DER. */
const pickOf = (leaf: Issued, sent: readonly Issued[], anchors: readonly Issued[], depth = 4) => {
	const picked = chosen(
		leaf.der,
		sent.map((s) => s.der),
		anchors.map((a) => a.der),
		depth,
	);
	if (picked.kind !== "chain") return picked.kind;
	return picked.chain
		.map((der) => new X509Certificate(der).subject.replace(/^CN=/, ""))
		.join(" > ");
};
/** One signed as `cn` by keys whose issuer is named `issuerCn`, as a client could make them. */
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

	it("takes no certificate with more than four issuers, nor more than ten sent, or the intermediates allowed and one more", async () => {
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
		const padding = await Promise.all(Array.from({ length: 9 }, (_, n) => issue({ cn: `p${n}` })));
		expect(pickOf(leaf, [first, ...padding], [root])).toBe("leaf > I > R");
		const more = await issue({ cn: "p9" });
		expect(pickOf(leaf, [first, ...padding, more], [root])).toBe("path");
		// With 14 intermediates allowed, a client may send 15.
		const extra = await Promise.all(Array.from({ length: 4 }, (_, n) => issue({ cn: `q${n}` })));
		const fifteen = [first, ...padding, more, ...extra];
		expect(pickOf(leaf, fifteen, [root], 14)).toBe("leaf > I > R");
		expect(pickOf(leaf, [...fifteen, await issue({ cn: "q4" })], [root], 14)).toBe("path");
	});

	it("prefers what was sent, in the order sent, and tells a path past the intermediates allowed", async () => {
		const root = await issue({ cn: "R", ca: true });
		const a = await issue({ cn: "a", by: root, ca: true });
		const b = await issue({ cn: "b", by: a, ca: true });
		const leaf = await issue({ cn: "leaf", by: b });
		expect(pickOf(leaf, [b, a], [root])).toBe("leaf > b > a > R");
		expect(pickOf(leaf, [b, a], [root], 1)).toBe("too many intermediates");
		// The root sent as well ends the path there, as the anchor it is.
		expect(pickOf(leaf, [b, a, root], [root])).toBe("leaf > b > a > R");
		expect(chosen(leaf.der, [b.der, new Uint8Array([1, 2])], [root.der], 4)).toEqual({
			kind: "malformed",
		});
	});

	it("finds no path for a leaf that is itself an anchor, as the engine alone found none before", async () => {
		const pinned = await issue({ cn: "client" });
		expect(pickOf(pinned, [], [pinned])).toBe("path");
	});
});
