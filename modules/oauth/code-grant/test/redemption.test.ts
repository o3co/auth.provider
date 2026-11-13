import { createHash } from "node:crypto";
import type { GrantInput } from "@mod/grants";
import { memoryRecords } from "@mod/records/testing";
import type { Sessions } from "@mod/session";
import { expect, it } from "vitest";
import { type CodeRecord, toStored } from "../src/codes.ts";
import { codeGrant } from "../src/grant.ts";
import { fromStoredRedemptionRecord } from "../src/redemption-record/redemption-record.ts";
import { type StoredCode, type StoredRedemptionRecord, storedRecordMaxMs } from "../src/store.ts";

const verifier = "v".repeat(43);
const issued: CodeRecord = {
	format: 2,
	state: "issued",
	clientId: "app",
	redirectUri: "https://app.example/cb",
	challenge: createHash("sha256").update(verifier).digest("base64url"),
	scope: ["read"],
	audience: ["https://api"],
	session: "s1",
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: 0,
};
const params: Record<string, string> = {
	code: "c1",
	redirect_uri: issued.redirectUri,
	code_verifier: verifier,
};

it("ends the token no later than the allowance before its redemption record ends, under a session that outlives it", async () => {
	let now = 5000;
	const codes = memoryRecords<StoredCode>(() => now, { shards: 1, perShard: 1 });
	const records = memoryRecords<StoredRedemptionRecord>(() => now, { shards: 1, perShard: 1 });
	await codes.records.create("c1", toStored(issued), 60_000);
	const asked: (number | undefined)[] = [];
	const grant = codeGrant({
		store: { nameOf: (code) => code, create: codes.records.create, update: codes.records.change },
		redemptionRecords: {
			create: (name, record, lifetimeMs) => records.records.create(name, record, lifetimeMs),
			read: records.records.read,
			update: records.records.change,
		},
		sessions: {
			entryOf: async () => ({ kind: "entered", endsAt: Number.POSITIVE_INFINITY }),
		} as unknown as Sessions,
		settle: async () => {},
		now: () => now,
		idToken: undefined,
		additions: [],
		redemptions: [],
		hooks: [],
	});
	const input = {
		client: { id: "app" },
		param: (name: string) => params[name],
		target: (audience: readonly string[]) => ({ kind: "audience", audience }),
		admits: async () => ({ kind: "allowed" }),
		issue: async (_grant: unknown, from?: { notAfter?: number }) => {
			asked.push(from?.notAfter);
			now += 1000;
			return {
				kind: "issued",
				access: { token: "t", id: "id", expiresAt: 9000, expiresIn: 4, tokenType: "Bearer" },
			};
		},
	} as unknown as GrantInput;
	expect((await grant.handle(input)).kind).toBe("issued");
	expect(asked).toEqual([5000 + storedRecordMaxMs - 120_000]);
	now = 5000 + storedRecordMaxMs - 1;
	expect(fromStoredRedemptionRecord(records.peek("c1"))?.token?.expiresAt).toBe(9000);
	now += 1;
	expect(records.peek("c1")).toBeUndefined();
});
