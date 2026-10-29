import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type FamilyStore,
	familyStore,
	issuedAccess,
	redemptionStore,
	type StoredFamily,
	type StoredLink,
	type StoredRedemption,
	sessionFamilies,
	settleList,
	tokenFamilies,
} from "../src/store.ts";

/** refresh's store interfaces on the records stand-in, with lifetimes on the composition's clock; the family store behind a switch. */
export function memoryStores(caps = { sessionFamilies: 1000, issuedAccess: 1000 }) {
	let clock = () => 0;
	const now = () => clock();
	const size = { shards: 4, perShard: 50 };
	const kept = memoryRecords<StoredFamily>(now, size);
	const marks = memoryRecords<StoredRedemption>(now, size);
	const links = memoryRecords<StoredLink>(now, size);
	const bySession = memoryRecords<never>(now, size).keyedSets(caps.sessionFamilies);
	const byFamily = memoryRecords<never>(now, size).keyedSets(caps.issuedAccess);
	const down = { families: unavailableSwitch<FamilyStore>("family store") };
	let meanwhile: ((id: string) => Promise<void>) | undefined;
	let beforeDone: ((id: string) => Promise<void>) | undefined;
	/** What redemptions and the settle list were given, as written. */
	const given: unknown[] = [];
	const module = defineModule({ name: "refresh-stores", replicaSafe: false, takes: [] }, (m) => [
		m.provide(familyStore).by((c) => {
			clock = c.clock.now;
			const { create: save, read, change } = kept.records;
			// An update that finds no record runs `meanwhile` once, as a write landing just after it.
			const update: FamilyStore["update"] = async (id, how) => {
				const changed = await change(id, how);
				const landing = meanwhile;
				meanwhile = undefined;
				if (!changed && landing) await landing(id);
				return changed;
			};
			return down.families.wrap({ save, read, update });
		}),
		m.provide(redemptionStore).by(() => ({
			save: (redemption, record, lifetimeMs) => {
				given.push([redemption, record]);
				return marks.records.create(redemption, record, lifetimeMs);
			},
			read: marks.records.read,
		})),
		m.provide(sessionFamilies).by(() => bySession),
		m.provide(issuedAccess).by(() => byFamily),
		m.provide(tokenFamilies).by(() => ({ save: links.records.create, read: links.records.read })),
		m.provide(settleList).by(() => ({
			...kept.deferred,
			add: (id: string) => {
				given.push(id);
				return kept.deferred.add(id);
			},
			done: async (id: string) => {
				const first = beforeDone;
				beforeDone = undefined;
				if (first) await first(id);
				return kept.deferred.done(id);
			},
		})),
	]);
	/** The next update that finds no record is followed by this write. */
	const landing = (write: (id: string) => Promise<void>) => {
		meanwhile = write;
	};
	/** The settle list's next `done` is preceded by this write, as another pass landing just before it. */
	const landingBeforeDone = (write: (id: string) => Promise<void>) => {
		beforeDone = write;
	};
	return {
		module,
		kept,
		marks,
		links,
		bySession,
		byFamily,
		down,
		landing,
		landingBeforeDone,
		given,
	};
}
