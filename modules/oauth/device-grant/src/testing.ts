import { randomUUID } from "node:crypto";
import type { Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { z } from "zod";
import type { section } from "./section.ts";
import type {
	ApprovalRecords,
	DeviceStore,
	StoredApproval,
	StoredDevice,
	UserCodes,
} from "./store.ts";

export type DeviceGrantSettings = z.input<typeof section>;

export function deviceGrantConfig(settings: Partial<DeviceGrantSettings> = {}) {
	return {
		"device-grant": { "verification-uri": "https://as.example/device", ...settings },
	};
}

/** An implementation of the store interfaces, with the hooks its contract test drives. */
export interface DevicePlace {
	readonly devices: DeviceStore;
	readonly userCodes: UserCodes;
	/** The place's approvals: checked as devices are, on the same clock and faults. */
	readonly approvals: ApprovalRecords;
	/** Where the devices can be walked: the walk a maintenance tool would hand in, over this store. */
	readonly walkOf?: () => Walk;
	/** Moves the store's clock on, so lifetimes run out. */
	advance(ms: number): void;
	/** Before the next update of `name` writes, another writer changes its record as given. */
	raceNextUpdate(name: string, change: (record: StoredDevice) => StoredDevice): void;
	/** Where answers can be lost: the next write takes effect, but its answer is lost. */
	readonly loseNextAnswer?: () => void;
	/** Where the store replicates: a replica takes over, keeping only what was confirmed. */
	readonly failover?: () => Promise<void>;
	/** Where the store can restart: it does, keeping only what it holds durably. */
	readonly restart?: () => Promise<void>;
	/** Where memory can run short: it does, keeping only what is kept from eviction. */
	readonly pressMemory?: () => Promise<void>;
	/** Where what the store was given can be searched: whether any of it carried `text`. */
	readonly holds?: (text: string) => boolean;
}

/**
 * What device-grant needs from any implementation of its store interfaces: devices and user codes
 * kept whole and once, devices changed only from what they hold, both ended at exactly their
 * lifetime, through lost answers, restarts, memory pressure and failovers.
 */
export function deviceStoreContract(name: string, open: () => Promise<DevicePlace>): void {
	const fresh = () => `d-${randomUUID()}`;
	const held = (value: object) => value as unknown as StoredDevice;
	const counted = (record: StoredDevice) => (record as unknown as { n: number }).n;
	const plus = (record: StoredDevice) => ({ value: held({ n: counted(record) + 1 }) });
	const approved = (value: object) => value as unknown as StoredApproval;
	/** What an approval holds, as the poll reads it: a confirmed change that writes nothing. */
	const readOf = async (approvals: ApprovalRecords, name: string) =>
		(await approvals.update(name, () => undefined))?.before;

	describe(`device-grant's store interfaces: ${name}`, () => {
		it("names a device code the same way every time, never as the code, and apart from another", async () => {
			const { devices } = await open();
			const [code, other] = [fresh(), fresh()];
			expect(devices.nameOf(code)).toBe(devices.nameOf(code));
			expect([code, devices.nameOf(other)]).not.toContain(devices.nameOf(code));
		});

		it("never gives a device code to what the store holds, in clear", async (context) => {
			const store = await open();
			const { holds } = store;
			if (!holds) return context.skip();
			const [code, userCode, kept] = [fresh(), fresh(), fresh()];
			const name = store.devices.nameOf(code);
			await store.devices.save(name, held({ kept }), 60_000);
			await store.devices.update(name, (record) => ({ value: record }));
			await store.userCodes.save(userCode, name, 60_000);
			expect([holds(kept), holds(name), holds(code)]).toEqual([true, true, false]);
		});

		it("keeps a device whole and once, and changes it only from what it holds", async () => {
			const store = await open();
			const name = fresh();
			const odd = held({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await store.devices.save(name, odd, 60_000)).toBe("created");
			expect(await store.devices.save(name, held({ n: 1 }), 60_000)).toBe("exists");
			expect(await store.devices.read(name)).toEqual(odd);
			expect(await store.devices.update(fresh(), plus)).toBeUndefined();
			const counting = fresh();
			await store.devices.save(counting, held({ n: 1 }), 60_000);
			store.raceNextUpdate(counting, (record) => held({ n: counted(record) * 10 }));
			expect(await store.devices.update(counting, plus)).toEqual({
				before: held({ n: 10 }),
				after: held({ n: 11 }),
			});
		});

		it("keeps a user code once, naming its device, and ends both at exactly their lifetime", async () => {
			const store = await open();
			const [name, code] = [fresh(), fresh()];
			await store.devices.save(name, held({ n: 1 }), 1000);
			expect(await store.userCodes.save(code, name, 1000)).toBe("created");
			expect(await store.userCodes.save(code, fresh(), 1000)).toBe("exists");
			expect(await store.userCodes.read(code)).toBe(name);
			expect(await store.userCodes.read(fresh())).toBeUndefined();
			store.advance(999);
			expect([await store.devices.read(name), await store.userCodes.read(code)]).toEqual([
				held({ n: 1 }),
				name,
			]);
			store.advance(1);
			expect([await store.devices.read(name), await store.userCodes.read(code)]).toEqual([
				undefined,
				undefined,
			]);
		});

		it("keeps devices and user codes through a restart and through memory pressure", async (context) => {
			const store = await open();
			const { restart, pressMemory } = store;
			if (!restart || !pressMemory) return context.skip();
			const [name, code] = [fresh(), fresh()];
			await store.devices.save(name, held({ n: 1 }), 60_000);
			await store.userCodes.save(code, name, 60_000);
			await restart();
			await pressMemory();
			expect(await store.devices.read(name)).toEqual(held({ n: 1 }));
			expect(await store.userCodes.read(code)).toBe(name);
		});

		it("keeps an approval whole and once per name, read as kept, for its lifetime exactly", async () => {
			const place = await open();
			const { approvals } = place;
			const [name, other] = [fresh(), fresh()];
			const odd = approved({ state: "unheard-of", nested: { list: [1, "two"] } });
			expect(await approvals.create(name, odd, 1000, "alice")).toBe("created");
			expect(await approvals.create(name, approved({ n: 1 }), 1000, "alice")).toBe("exists");
			expect([await readOf(approvals, name), await readOf(approvals, other)]).toEqual([
				odd,
				undefined,
			]);
			place.advance(999);
			expect(await readOf(approvals, name)).toEqual(odd);
			place.advance(1);
			expect(await readOf(approvals, name)).toBeUndefined();
			expect(await approvals.create(name, approved({ n: 2 }), 1000, "alice")).toBe("created");
		});

		it("answers a change of an approval that writes nothing from what is kept, confirmed, through lost answers and a failover", async () => {
			const place = await open();
			const { approvals, loseNextAnswer: lose, failover } = place;
			const { update } = approvals;
			const [kept, gone] = [fresh(), fresh()];
			await approvals.create(kept, approved({ n: 1 }), 60_000, "alice");
			const nothing = () => undefined;
			expect(await update.call(approvals, kept, nothing)).toEqual({
				before: approved({ n: 1 }),
				after: approved({ n: 1 }),
			});
			expect(await update.call(approvals, gone, nothing)).toBeUndefined();
			if (!lose || !failover) return;
			lose();
			expect((await update.call(approvals, kept, nothing))?.before).toEqual(approved({ n: 1 }));
			await failover();
			expect((await update.call(approvals, kept, nothing))?.before).toEqual(approved({ n: 1 }));
		});

		it("keeps approvals through a restart, memory pressure, lost answers and a failover", async (context) => {
			const place = await open();
			const { approvals, restart, pressMemory, loseNextAnswer: lose, failover } = place;
			if (!restart || !pressMemory || !lose || !failover) return context.skip();
			const [kept, settled] = [fresh(), fresh()];
			await approvals.create(kept, approved({ n: 1 }), 60_000, "alice");
			await restart();
			await pressMemory();
			lose();
			expect(await approvals.create(settled, approved({ n: 2 }), 60_000, "alice")).toBe("created");
			await failover();
			expect(await readOf(approvals, kept)).toEqual(approved({ n: 1 }));
			expect(await readOf(approvals, settled)).toEqual(approved({ n: 2 }));
		});

		it("walks every device record, handing each over, and stops where the visitor does", async (context) => {
			const place = await open();
			const { walk } = place.devices;
			if (!walk || !place.walkOf) return context.skip();
			const signal = new AbortController().signal;
			const names = [fresh(), fresh(), fresh()];
			for (const [n, name] of names.entries()) await place.devices.save(name, held({ n }), 60_000);
			const seen: number[] = [];
			const all = await walk.call(
				place.devices,
				place.walkOf(),
				(r) => (seen.push(counted(r)), true),
				signal,
			);
			expect(all).toEqual({ kind: "walked" });
			expect(seen.sort()).toEqual(expect.arrayContaining([0, 1, 2]));
			let left = 1;
			const one = await walk.call(place.devices, place.walkOf(), () => left-- > 0, signal);
			expect(one).toEqual({ kind: "stopped" });
		});

		// Each interface fails over after its own writes: a later write in another space would
		// confirm them, and hide a space that does not replicate.
		it("settles writes whose answers were lost, and keeps each interface's through a failover", async (context) => {
			const store = await open();
			const { loseNextAnswer: lose, failover } = store;
			if (!lose || !failover) return context.skip();
			const [name, code] = [fresh(), fresh()];
			lose();
			expect(await store.devices.save(name, held({ n: 1 }), 60_000)).toBe("created");
			lose();
			expect((await store.devices.update(name, plus))?.after).toEqual(held({ n: 2 }));
			await failover();
			expect(await store.devices.read(name)).toEqual(held({ n: 2 }));
			lose();
			expect(await store.userCodes.save(code, name, 60_000)).toBe("created");
			await failover();
			expect(await store.userCodes.read(code)).toBe(name);
		});
	});
}
