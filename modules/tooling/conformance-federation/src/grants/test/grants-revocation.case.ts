import { randomBytes } from "node:crypto";
import { areaTarget } from "@mod/conformance";
import { ledgerRevocation } from "@mod/conformance-identity";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type GrantsTarget, grantsTarget } from "./grants.ts";

const credential = randomBytes(32).toString("base64url");
let t: GrantsTarget;
let base = "";

/** The ledger's revocation of a subject, from its block over https, as its proxy forwards it. */
async function revoke(subject: string) {
	const res = await fetch(`${base}/ledger/subject-revocations`, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for": "198.51.100.30",
			authorization: `Bearer ${credential}`,
		},
		body: JSON.stringify({ subject }),
	});
	return res.status;
}

describe.runIf(areaTarget().can(ledgerRevocation))(
	"federation grants: a subject the ledger revokes",
	() => {
		beforeAll(async () => {
			t = await grantsTarget({}, { revocations: { credential, sources: ["198.51.100.0/24"] } });
			base = t.base;
		});
		afterAll(async () => {
			await t?.stop();
		});

		it("ends the subject's grants and pending intents, and leaves another subject's", async () => {
			const { id } = await t.connected();
			expect((await t.grantCall(id, "token")).status).toBe(200);
			const pending = String((await t.lodge()).body.grant_id);
			const bobs = String((await t.lodge({ sub: "bob" })).body.grant_id);
			expect(await revoke("alice")).toBe(200);
			const token = await t.grantCall(id, "token");
			expect([token.status, token.body.error]).toEqual([410, "grant_revoked"]);
			expect((await t.grantCall(id, "status")).body.status).toBe("revoked");
			expect((await t.grantCall(pending, "status")).body.status).toBe("revoked");
			expect((await t.grantCall(bobs, "status", { sub: "bob" })).body.status).toBe("pending");
		});
	},
);
