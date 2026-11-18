import { randomBytes } from "node:crypto";
import { isUnavailable } from "@mod/kernel";
import { expect, it } from "vitest";
import { z } from "zod";
import { memoryStores, writeToken } from "../../../test/stores.ts";
import { holderOf, stored } from "../../records/records.ts";
import { keptPasskeys } from "../../records.ts";
import type { PasskeyOp, PasskeyStore } from "../../store.ts";
import { portsRefused, registrationPortsRefused } from "../ports.ts";

const fresh = () => randomBytes(32).toString("base64url");
const credential = (id: string, userHandle: string) => ({
	id,
	publicKey: "pQ",
	signCount: 0,
	userHandle,
	backupEligible: false,
	backedUp: false,
});

/** Passkey records over memory stores whose `updateAsOne` keeps every op it is given, by place. */
function watchingOps() {
	const stores = memoryStores();
	const ops: { place: string; op: PasskeyOp }[] = [];
	const store: PasskeyStore = {
		...stores.passkeys,
		updateAsOne: (p) =>
			stores.passkeys.updateAsOne({
				...p,
				decide: (read, watched) => {
					const decided = p.decide(read, watched);
					ops.length = 0;
					for (const [n, op] of (decided.targets ?? []).entries()) {
						if (op) ops.push({ place: p.targets[n]?.place ?? "", op });
					}
					return decided;
				},
			}),
	};
	return { stores, ops, records: keptPasskeys(store, writeToken) };
}

it("states the ports a passkey store must offer: erase and migrate in both spaces or none", () => {
	const { passkeys } = memoryStores();
	const { updateAsOne } = passkeys;
	const erasing = { erase: async () => ({}) as never, migrate: async () => ({}) as never };
	expect(portsRefused(passkeys)).toBeUndefined();
	const both = {
		credentials: { ...passkeys.credentials, ...erasing },
		subjects: { ...passkeys.subjects, ...erasing },
	};
	expect(portsRefused({ ...both, updateAsOne })).toBeUndefined();
	const part = { ...both, subjects: { ...passkeys.subjects, erase: erasing.erase } };
	expect(portsRefused({ ...part, updateAsOne })).toMatch(/part of erase and migrate/);
});

it("writes a list's change through updateAsOne: a record none holds created for its subject, a held one moved to it", async () => {
	const { records, ops } = watchingOps();
	const [id, other] = [fresh(), fresh()];
	const handle = await records.handleFor("sam", fresh());
	expect(await records.joined("sam", credential(id, handle), 10, undefined, "w1")).toBe("written");
	expect(ops.map(({ place, op }) => [place, op.kind, "subject" in op ? op.subject : op])).toEqual([
		["credentials", "create", "sam"],
		["subjects", "move", expect.objectContaining({ to: "sam" })],
	]);
	// A record another subject's removal left, taken over: moved to the one registering.
	await records.joined("sam", credential(other, handle), 10, undefined, "w2");
	await records.removed("sam", other);
	const bobs = await records.handleFor("bob", fresh());
	expect(await records.joined("bob", credential(other, bobs), 10, undefined, "w3")).toBe("written");
	expect(ops[0]).toMatchObject({ place: "credentials", op: { kind: "move", to: "bob" } });
});

it("takes a change as one refused as unavailable", async () => {
	const { passkeys } = memoryStores();
	const refusing: PasskeyStore = {
		...passkeys,
		updateAsOne: async () => ({ kind: "refused", at: { in: "targets", nth: 0 }, why: "erased" }),
	};
	const records = keptPasskeys(refusing, writeToken);
	const handle = await records.handleFor("sam", fresh());
	await expect(
		records.joined("sam", credential(fresh(), handle), 10, undefined, "w"),
	).rejects.toSatisfy(isUnavailable);
});

// 0.19.1's holder, frozen: the shape it reads, and its three writes that rewrite a holder, each
// spreading the record it read. A holder 0.20 writes carries its subject through all of them.
const holder0191 = z.object({
	v: z.literal(1),
	handle: z.string(),
	credentials: z.array(z.string()),
	fence: z.number().int().min(0).optional(),
});
const rewrites0191 = {
	joined: (ours: object, list: string[]) => ({ ...ours, credentials: list }),
	listing: (ours: object, list: string[], fence: number) => ({ ...ours, credentials: list, fence }),
	cleared: (ours: object, fence: number) => ({ ...ours, credentials: [], fence: fence + 1 }),
};

it("writes a holder a 0.19.1 node reads and rewrites keeping its subject; one that node makes holds none", async () => {
	const { stores, records } = watchingOps();
	await records.handleFor("sam", fresh());
	const written = stores.holderCopy("sam") as object;
	expect(holder0191.safeParse(written).success).toBe(true);
	for (const rewritten of [
		rewrites0191.joined(written, ["a"]),
		rewrites0191.listing(written, [], 1),
		rewrites0191.cleared(written, 1),
	]) {
		expect(holderOf(stored(rewritten)).subject).toBe("sam");
	}
	// A holder a 0.19 node made holds no subject: 0.20 reads it, and its next write names one.
	const handle = fresh();
	await stores.backTo("ann", { v: 1, handle, credentials: [] });
	expect(holderOf(stored(stores.holderCopy("ann") as object)).subject).toBeUndefined();
	await records.joined("ann", credential(fresh(), handle), 10, undefined, "w");
	expect(holderOf(stored(stores.holderCopy("ann") as object)).subject).toBe("ann");
});

it("states the registration challenge store's ports: erase and migrate both, or neither", () => {
	const { registrations } = memoryStores();
	const erase = async () => ({}) as never;
	const migrate = async () => ({}) as never;
	expect(registrationPortsRefused(registrations)).toBeUndefined();
	expect(registrationPortsRefused({ ...registrations, erase, migrate })).toBeUndefined();
	expect(registrationPortsRefused({ ...registrations, erase })).toMatch(/one of erase and migrate/);
	expect(registrationPortsRefused({ ...registrations, migrate })).toMatch(
		/one of erase and migrate/,
	);
});
