import type { Users } from "@mod/users";
import { describe, expect, it } from "vitest";
import { upstreamAccountWith } from "../upstream-account.ts";

const at = { issuer: "https://corp.example", subject: "u-alice" };
const grant = { subject: "alice" };
/** A ledger answering who holds an upstream identity: a subject, nobody, or a throw. */
const ledger = (holds: string | "nobody" | Error) =>
	({
		byUpstream: async () => {
			if (holds instanceof Error) throw holds;
			return holds === "nobody"
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

	it("checks the holder only where the identity check is required, and says which check it makes", async () => {
		const required = upstreamAccountWith({ users: ledger("bob"), check: "required" });
		expect(required.check).toBe("required");
		expect(await required.refusal(grant, {}, "corp", at)).toBe("identity_conflict");
		const none = upstreamAccountWith({ users: ledger("bob"), check: "none" });
		expect(none.check).toBe("none");
		expect(await none.refusal(grant, {}, "corp", at)).toBeUndefined();
		const nobody = upstreamAccountWith({ users: ledger("nobody"), check: "required" });
		expect(await nobody.refusal(grant, {}, "corp", at)).toBeUndefined();
	});

	it("reads any failure of the ledger as unverifiable", async () => {
		const failing = upstreamAccountWith({ users: ledger(new TypeError("x")), check: "required" });
		expect(await failing.refusal(grant, {}, "corp", at)).toBe("identity_unverifiable");
	});
});
