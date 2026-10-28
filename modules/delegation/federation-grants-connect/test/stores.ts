import {
	type GrantStore,
	grantStore,
	type PendingIntents,
	pendingIntents,
	type RefreshLockStore,
	refreshLockStore,
	type StepStore,
	type StoredGrant,
	type StoredStep,
	type SubjectGrants,
	stepStore,
	subjectGrants,
} from "@mod/federation-grants";
import { defineModule } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";

/** federation-grants' stores on the records stand-in, on the given clock; the grants behind a switch. */
export function memoryStores(now: () => number = () => 0, cap = 16) {
	const size = { shards: 1, perShard: 1 };
	const grants = memoryRecords<StoredGrant>(now, size);
	const steps = memoryRecords<StoredStep>(now, size);
	// Locks see real time pass on top of the test's clock, as a store's do: a lock let go ends a millisecond later.
	const started = Date.now();
	const held = memoryRecords<string>(() => now() + (Date.now() - started), size).records;
	const sets = memoryRecords<true>(now, size).keyedSets(cap);
	const listed = memoryRecords<true>(now, size).keyedSets(100);
	const down = unavailableSwitch<GrantStore>("records");
	const grantRecords: GrantStore = down.wrap({
		create: grants.records.create,
		read: grants.records.read,
		change: grants.records.change,
		// One grant a page, so a walk must go on by its cursor.
		scan: async (cursor) => {
			const keys = (await grants.records.scan()).keys.toSorted();
			const at = cursor === undefined ? 0 : keys.indexOf(cursor) + 1;
			const page = keys.slice(at, at + 1);
			const last = page[0];
			return at + 1 < keys.length && last !== undefined
				? { keys: page, cursor: last }
				: { keys: page };
		},
	});
	const stepRecords: StepStore = {
		create: steps.records.create,
		read: steps.records.read,
		change: steps.records.change,
	};
	const pending: PendingIntents = { add: sets.add, remove: sets.remove };
	const subjects: SubjectGrants = listed;
	const lockStore: RefreshLockStore = {
		hold: (name, mark, lifetimeMs) => held.create(name, mark, lifetimeMs),
		update: held.change,
	};
	const module = defineModule(
		{ name: "federation-grants-stores", replicaSafe: false, takes: [] },
		(m) => [
			m.provide(grantStore).by(() => grantRecords),
			m.provide(stepStore).by(() => stepRecords),
			m.provide(pendingIntents).by(() => pending),
			m.provide(subjectGrants).by(() => subjects),
			m.provide(refreshLockStore).by(() => lockStore),
		],
	);
	return {
		module,
		grants: grantRecords,
		steps: stepRecords,
		pending,
		subjects,
		lockStore,
		down,
		raceNext: grants.raceNextChange,
		peek: grants.peek,
	};
}
