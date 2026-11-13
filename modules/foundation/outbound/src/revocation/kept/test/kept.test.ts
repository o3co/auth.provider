import type { VerifiedCrl } from "@mod/x509-path";
import { describe, expect, it } from "vitest";
import { keptOver } from "../kept.ts";

/** A verified CRL as kept reads it: its times, its number, and how many serials it lists. */
const crl = (thisUpdate: number, number?: number, listed = 0): VerifiedCrl =>
	({
		issuer: {},
		thisUpdate,
		nextUpdate: thisUpdate + 3_600_000,
		...(number === undefined ? {} : { number: BigInt(number) }),
		listed: { size: listed },
	}) as unknown as VerifiedCrl;

describe("an issuer's high-water mark", () => {
	it("refuses a lower CRLNumber, an older this update, and one without a number after one was seen", () => {
		const kept = keptOver(8);
		expect(kept.take("a", crl(1000, 5))).toBe("kept");
		expect(kept.take("a", crl(2000, 4))).toBe("rollback");
		expect(kept.take("a", crl(500, 6))).toBe("rollback");
		expect(kept.take("a", crl(2000))).toBe("rollback");
		expect(kept.take("a", crl(2000, 6))).toBe("kept");
		// Without a number ever: by this update alone.
		expect(kept.take("b", crl(1000))).toBe("kept");
		expect(kept.take("b", crl(999))).toBe("rollback");
		expect(kept.take("b", crl(1000, 1))).toBe("kept");
	});

	it("keeps the one kept for the same CRLNumber, and takes it again once evicted, its next update its own", () => {
		const kept = keptOver(1);
		const first = crl(1000, 5);
		expect(kept.take("a", first)).toBe("kept");
		expect(kept.take("a", crl(1500, 5))).toBe("same");
		expect(kept.crlOf("a")).toBe(first);
		// Another issuer's CRL evicts it; its mark stays.
		expect(kept.take("b", crl(1000, 1))).toBe("kept");
		expect(kept.crlOf("a")).toBeUndefined();
		expect(kept.take("a", crl(1000, 4))).toBe("rollback");
		const again = crl(1000, 5);
		expect(kept.take("a", again)).toBe("kept");
		expect(kept.crlOf("a")?.nextUpdate).toBe(again.nextUpdate);
	});

	it("is never evicted: past 4,096 issuers a new one's CRL is not taken, and those marked go on", () => {
		const kept = keptOver(1024);
		for (let n = 0; n < 4096; n++) expect(kept.take(`i${n}`, crl(1000, 1))).toBe("kept");
		expect(kept.take("new", crl(1000, 1))).toBe("state-full");
		expect(kept.take("i0", crl(2000, 2))).toBe("kept");
	});
});

describe("revocations seen", () => {
	it("are kept never evicted; past 4,096, the issuer's good is no longer taken, and a CRL's own listing takes none of them", () => {
		const kept = keptOver(8);
		// A CRL listing 100,000 serials records none of them.
		expect(kept.take("a", crl(1000, 1, 100_000))).toBe("kept");
		for (let n = 0; n < 4096; n++) kept.recordRevoked("a", `s${n}`);
		expect(kept.isUnrecorded("a")).toBe(false);
		expect(kept.isRevoked("a", "s0")).toBe(true);
		kept.recordRevoked("a", "s0");
		expect(kept.isUnrecorded("a")).toBe(false);
		kept.recordRevoked("a", "one more");
		expect([kept.isRevoked("a", "one more"), kept.isUnrecorded("a")]).toEqual([false, true]);
	});
});

describe("CRLs kept", () => {
	it("hold their listed serials to 2^19 together, the oldest going first, and one past it alone is not taken", () => {
		const kept = keptOver(8);
		const half = 2 ** 18;
		expect(kept.take("a", crl(1000, 1, half))).toBe("kept");
		expect(kept.take("b", crl(1000, 1, half))).toBe("kept");
		expect(kept.take("c", crl(1000, 1, 1))).toBe("kept");
		expect(["a", "b", "c"].map((issuer) => kept.crlOf(issuer) !== undefined)).toEqual([
			false,
			true,
			true,
		]);
		expect(kept.take("d", crl(1000, 1, 2 ** 19 + 1))).toBe("too-large");
		expect(kept.crlOf("b")).toBeDefined();
	});

	it("are held to crl-entries, the oldest going first", () => {
		const kept = keptOver(2);
		for (const issuer of ["a", "b", "c"]) kept.take(issuer, crl(1000, 1));
		expect(["a", "b", "c"].map((issuer) => kept.crlOf(issuer) !== undefined)).toEqual([
			false,
			true,
			true,
		]);
	});
});
