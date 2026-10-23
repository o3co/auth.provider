import { expect, it } from "vitest";
import type { StoredPasskey } from "../src/store.ts";
import { challengeStoreContract, passkeyStoreContract } from "../src/testing.ts";
import { memoryStores } from "./stores.ts";

passkeyStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		passkeys: stand.passkeys,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceSubjects(change),
	};
});

passkeyStoreContract("records stand-in changing records of both spaces as one", async () => {
	let now = 0;
	const stand = memoryStores(() => now, { together: true });
	return {
		passkeys: stand.passkeys,
		advance: (ms) => {
			now += ms;
		},
		raceNextUpdate: (_key, change) => stand.raceSubjects(change),
	};
});

challengeStoreContract("records stand-in", async () => {
	let now = 0;
	const stand = memoryStores(() => now);
	return {
		challenges: stand.challenges,
		advance: (ms) => {
			now += ms;
		},
	};
});

it("runs a change the stand-in races on what it read, then again on the other writer's, in either space", async () => {
	const stand = memoryStores();
	const asStored = (n: number) => ({ n }) as unknown as StoredPasskey;
	const inputs: unknown[] = [];
	const plusOne = (record: StoredPasskey) => {
		inputs.push(record);
		return { value: asStored((record as unknown as { n: number }).n + 1) };
	};
	await stand.passkeys.subjects.save("k", asStored(1), "endless");
	await stand.passkeys.credentials.save("k", asStored(1), "endless");
	stand.raceSubjects(() => asStored(10));
	expect((await stand.passkeys.subjects.update("k", plusOne))?.after).toEqual(asStored(11));
	stand.raceCredentials(() => asStored(20));
	expect((await stand.passkeys.credentials.update("k", plusOne))?.after).toEqual(asStored(21));
	expect(inputs).toEqual([asStored(1), asStored(10), asStored(1), asStored(20)]);
});

it("keeps a race for its own space waiting while the record it would change is missing", async () => {
	const stand = memoryStores();
	const asStored = (n: number) => ({ n }) as unknown as StoredPasskey;
	const inputs: unknown[] = [];
	const plusOne = (record: StoredPasskey) => {
		inputs.push(record);
		return { value: asStored((record as unknown as { n: number }).n + 1) };
	};
	await stand.passkeys.credentials.save("c", asStored(1), "endless");
	await stand.passkeys.subjects.save("s", asStored(5), "endless");
	stand.raceSubjects(() => asStored(50));
	// No such subject: nothing changes, and the race waits for the subjects' next update.
	expect(await stand.passkeys.subjects.update("missing", plusOne)).toBeUndefined();
	// A credential's update meets no race of the subjects'.
	expect((await stand.passkeys.credentials.update("c", plusOne))?.after).toEqual(asStored(2));
	expect((await stand.passkeys.subjects.update("s", plusOne))?.after).toEqual(asStored(51));
	expect(inputs).toEqual([asStored(1), asStored(5), asStored(50)]);
});

it("keeps a race for its own space waiting where the change throws, never leaking it to the other space", async () => {
	const stand = memoryStores();
	const asStored = (n: number) => ({ n }) as unknown as StoredPasskey;
	const plusOne = (record: StoredPasskey) => ({
		value: asStored((record as unknown as { n: number }).n + 1),
	});
	await stand.passkeys.credentials.save("c", asStored(1), "endless");
	await stand.passkeys.subjects.save("s", asStored(5), "endless");
	stand.raceSubjects(() => asStored(50));
	await expect(
		stand.passkeys.subjects.update("s", () => {
			throw new Error("the change refuses");
		}),
	).rejects.toThrow("the change refuses");
	expect((await stand.passkeys.credentials.update("c", plusOne))?.after).toEqual(asStored(2));
	expect((await stand.passkeys.subjects.update("s", plusOne))?.after).toEqual(asStored(51));
});
