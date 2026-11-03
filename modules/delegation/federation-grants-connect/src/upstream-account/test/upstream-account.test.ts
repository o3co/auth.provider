import type { Users } from "@mod/users";
import { describe, expect, it } from "vitest";
import { upstreamAccountWith } from "../upstream-account.ts";

const at = { issuer: "https://corp.example", subject: "u-alice" };
const grant = { subject: "alice" };
/** A ledger answering who holds an upstream identity: a subject, nobody (undefined), or a throw. */
const ledger = (holds: string | undefined | Error) =>
	({
		byUpstream: async () => {
			if (holds instanceof Error) throw holds;
			return holds === undefined
				? { kind: "none" }
				: { kind: "user", user: { subject: holds, attributes: {} } };
		},
	}) as unknown as Pick<Users, "byUpstream">;

describe("whose upstream account a connection reached", () => {
	it("is the grant's own when it matches what the grant and its intent hold", async () => {
		const account = upstreamAccountWith({ users: ledger("alice"), check: "required" });
		expect(await account.refusal({ ...grant, upstream: at }, {}, "corp", at)).toBeUndefined();
		expect(
			await account.refusal(grant, { expectedUpstream: "u-alice" }, "corp", at),
		).toBeUndefined();
	});

	it("is a mismatch where the grant holds another account, or its intent expects another", async () => {
		const account = upstreamAccountWith({ users: ledger("alice"), check: "none" });
		const other = { issuer: at.issuer, subject: "u-bob" };
		expect(await account.refusal({ ...grant, upstream: other }, {}, "corp", at)).toBe(
			"account_mismatch",
		);
		expect(await account.refusal(grant, { expectedUpstream: "u-bob" }, "corp", at)).toBe(
			"account_mismatch",
		);
	});

	it("compares no subject across issuers: another issuer's holds nothing, the identity check stays, and a subject expected of the grant's issuer refuses", async () => {
		const before = { issuer: "https://before.example", subject: "u-before" };
		const none = upstreamAccountWith({ users: ledger(undefined), check: "none" });
		expect(await none.refusal({ ...grant, upstream: before }, {}, "corp", at)).toBeUndefined();
		// The same string at another issuer is no one in particular, so it is no match either.
		const alike = { issuer: before.issuer, subject: at.subject };
		expect(
			await none.refusal({ ...grant, upstream: alike }, { expectedUpstream: at.subject }, "corp", at),
		).toBe("account_mismatch");
		const held = upstreamAccountWith({ users: ledger("bob"), check: "required" });
		expect(await held.refusal({ ...grant, upstream: before }, {}, "corp", at)).toBe(
			"identity_conflict",
		);
	});

	it("checks the holder only where the identity check is required, and says which check it makes", async () => {
		const required = upstreamAccountWith({ users: ledger("bob"), check: "required" });
		expect(required.check).toBe("required");
		expect(await required.refusal(grant, {}, "corp", at)).toBe("identity_conflict");
		const none = upstreamAccountWith({ users: ledger("bob"), check: "none" });
		expect(none.check).toBe("none");
		expect(await none.refusal(grant, {}, "corp", at)).toBeUndefined();
		const nobody = upstreamAccountWith({ users: ledger(undefined), check: "required" });
		expect(await nobody.refusal(grant, {}, "corp", at)).toBeUndefined();
	});

	it("tells a holder from no holder by the ledger's answer, whatever the holder's subject reads", async () => {
		for (const subject of ["nobody", "", "none"]) {
			const other = upstreamAccountWith({ users: ledger(subject), check: "required" });
			expect(await other.refusal(grant, {}, "corp", at)).toBe("identity_conflict");
		}
	});

	it("reads any failure of the ledger as unverifiable", async () => {
		const failing = upstreamAccountWith({ users: ledger(new TypeError("x")), check: "required" });
		expect(await failing.refusal(grant, {}, "corp", at)).toBe("identity_unverifiable");
	});
});
