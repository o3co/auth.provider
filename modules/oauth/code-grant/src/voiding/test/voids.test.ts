import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import type { Tokens } from "@mod/tokens";
import { expect, it } from "vitest";
import { type CodeRecord, fromStored, toStored } from "../../codes.ts";
import type { Addition } from "../../contract.ts";
import type { RedemptionRecords, StoredCode, StoredRedemptionRecord } from "../../store.ts";
import { voiding } from "../voiding.ts";

/**
 * A code used up by a 0.19 instance, which kept its token on the code: listed void, it is settled
 * once the token is revoked, though no redemption record holds it.
 */
const used: CodeRecord = {
	format: 2,
	state: "consumed",
	clientId: "app",
	redirectUri: "https://app.example/cb",
	challenge: "c",
	scope: ["read"],
	audience: ["https://api"],
	session: "s1",
	subject: "alice",
	amr: ["pwd"],
	authenticatedAt: 0,
	token: { reference: "ref-1", expiresAt: 60_000 },
};

it("settles a listed void alike whichever instance's sweep reaches it, both at once among them", async () => {
	const stand = memoryRecords<StoredCode>(() => 0, { shards: 1, perShard: 10 });
	const none = memoryRecords<StoredRedemptionRecord>(() => 0, { shards: 1, perShard: 10 });
	const redemptionRecords: RedemptionRecords = {
		create: none.records.create,
		read: none.records.read,
		update: none.records.change,
	};
	await stand.records.create("n1", toStored(used), 60_000);
	await stand.deferred.add("n1");
	const logged = recordingLog();
	const revoked: string[] = [];
	const ended: string[] = [];
	/** One instance's sweep, over the store and void list every instance shares. */
	const instance = () =>
		voiding({
			store: { nameOf: (code) => code, create: stand.records.create, update: stand.records.change },
			redemptionRecords,
			voids: stand.deferred,
			tokens: {
				revokeReferenced: async (reference: string) => {
					revoked.push(reference);
					return { kind: "revoked" };
				},
			} as unknown as Tokens,
			log: logged.log,
			additions: [
				{
					field: "extra",
					issue: async () => undefined,
					revoke: async (name) => {
						ended.push(name);
					},
				} satisfies Addition,
			],
		});
	const [one, other] = [instance(), instance()];
	await Promise.all([one.sweep(), other.sweep()]);
	await other.sweep();
	// Void, its token revoked and what was added ended, at most once by each instance, and no longer listed.
	expect(fromStored((await stand.records.read("n1")) as StoredCode)?.void).toBe(true);
	expect([new Set(revoked), revoked.length <= 2]).toEqual([new Set(["ref-1"]), true]);
	expect([new Set(ended), ended.length <= 2]).toEqual([new Set(["n1"]), true]);
	expect(stand.pending()).toEqual([]);
	expect(logged.lines()).toEqual([]);
});
