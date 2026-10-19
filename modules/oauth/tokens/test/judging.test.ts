import { expect, it } from "vitest";
import type { IssuancePolicy, IssuanceRequest } from "../src/contract.ts";
import { judging } from "../src/issuance.ts";

const request = (): IssuanceRequest => ({
	grant: { subject: "alice", issuedTo: "app", audience: ["https://api.example"], scope: ["read"] },
	grantType: "test",
});

it("hands each policy a frozen copy of the request, so none can change what another or the issuing sees", async () => {
	const seen: unknown[] = [];
	const writer: IssuancePolicy = {
		name: "a-writer",
		judge: async (asked) => {
			const loose = asked as unknown as { grant: { scope: string[]; subject: string } };
			// Past the readonly type: a policy that tries to widen what is issued.
			try {
				loose.grant.scope.push("admin");
				loose.grant.subject = "mallory";
			} catch {}
			return { kind: "allowed" };
		},
	};
	const reader: IssuancePolicy = {
		name: "b-reader",
		judge: async (asked) => {
			seen.push(structuredClone(asked.grant));
			return { kind: "allowed" };
		},
	};
	const given = request();
	expect(await judging([reader, writer], () => 0)(given)).toEqual({ kind: "allowed" });
	expect(seen).toEqual([request().grant]);
	expect(given).toEqual(request());
});
