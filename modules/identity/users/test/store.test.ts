import { describe, expect, it } from "vitest";
import type { RecordStore, StoredContacts, StoredLink } from "../src/contract.ts";
import { contactStoreContract, linkStoreContract, memoryUsersStores } from "../src/testing.ts";

const harness = <T>(kept: {
	store: RecordStore<T>;
	raceNextUpdate: (key: string, change: (record: T) => T) => void;
}) => ({ records: kept.store, advance: () => {}, raceNextUpdate: kept.raceNextUpdate });

linkStoreContract("memory stand-in", async () => harness(memoryUsersStores().links));
contactStoreContract("memory stand-in", async () => harness(memoryUsersStores().contacts));

describe("memory stand-in", () => {
	it("keeps copies, as a store does", async () => {
		const { store } = memoryUsersStores().contacts;
		const record = [{ kind: "email", value: "a@example.com" }];
		await store.save("s", record as unknown as StoredContacts, "endless");
		record.push({ kind: "email", value: "b@example.com" });
		((await store.read("s")) as unknown as unknown[]).push("c");
		expect(await store.read("s")).toEqual([{ kind: "email", value: "a@example.com" }]);
	});

	it("races only the next update of the key it names", async () => {
		const { store, raceNextUpdate } = memoryUsersStores().links;
		const record = (n: number) => ({ n }) as unknown as StoredLink;
		const count = (held: StoredLink) => (held as unknown as { n: number }).n;
		const plus = (held: StoredLink) => ({ value: record(count(held) + 1) });
		await store.save("a", record(1), "endless");
		await store.save("b", record(1), "endless");
		raceNextUpdate("a", (held) => record(count(held) * 10));
		expect((await store.update("b", plus))?.after).toEqual(record(2));
		expect((await store.update("a", plus))?.after).toEqual(record(11));
		expect((await store.update("a", plus))?.after).toEqual(record(12));
	});
});
