import {
	approvalRecordMaxMs,
	approvalRecords,
	type approvalRecordsNeeds,
	deviceStore,
	type deviceStoreNeeds,
	type StoredApproval,
	type StoredDevice,
	userCodes,
} from "@mod/device-grant";
import { contract, defineModule, optional, probes } from "@mod/kernel";
import { recordsIn, secretRecordsIn } from "@mod/records";
import { type Guarantee, type Space, spaces, store, storeControl } from "@mod/store";
import {
	indexSpaceOf,
	phasedRecordsIn,
	subjectRecordsPhase,
	tombstoneFloor,
} from "@mod/subject-records";

/** Each need device-grant states, as what meets it: a guarantee its space declares, or records under a secret. */
const { namesFromSecret: recordsFor, ...guaranteeFor } = {
	neverEvicted: "no-eviction",
	survivesCrash: "durable",
	survivesFailover: "replicated",
	namesFromSecret: secretRecordsIn,
} satisfies Record<keyof typeof deviceStoreNeeds, Guarantee | typeof secretRecordsIn>;
const guarantees = Object.values(guaranteeFor);
/** Each need device-grant states for its approvals, as the guarantee their space declares. */
const approvalGuaranteeFor: Record<keyof typeof approvalRecordsNeeds, Guarantee> = {
	neverEvicted: guaranteeFor.neverEvicted,
	survivesCrash: guaranteeFor.survivesCrash,
	survivesFailover: guaranteeFor.survivesFailover,
};
/**
 * Devices hold no subject from 0.20; a record a 0.19 instance approved keeps its approval's subject,
 * at most 7,200 s, and device-grant's migration stops until none is left.
 */
const devices: Space = { name: "device-grant-store.devices", guarantees, subjectData: "none" };
const codes: Space = { name: "device-grant-store.user-codes", guarantees, subjectData: "none" };
/** Each approval, by its device's name (a digest): `bounded` by `approvalRecordMaxMs`, fenced at creation by its subject's tombstone, erased by device-grant, at the tombstone's floor. */
const approvals: Space = {
	name: "device-grant-store.approvals",
	guarantees: [...new Set([...Object.values(approvalGuaranteeFor), ...tombstoneFloor])],
	subjectData: "bounded",
	boundedMs: approvalRecordMaxMs,
	erasedBy: "device-grant",
};

/** The approvals' records over the phase this process reads once. */
const placed = contract<Awaited<ReturnType<typeof phasedRecordsIn<StoredApproval>>>>(
	"device-grant-store.placed",
);

export default defineModule(
	{ name: "device-grant-store", replicaSafe: true, takes: [store, optional(storeControl)] },
	(m) => [
		m.contribute(spaces).by(() => devices),
		m.contribute(spaces).by(() => codes),
		m.contribute(spaces).by(() => approvals),
		m.contribute(spaces).by(() => indexSpaceOf(approvals)),
		m.provide(deviceStore).by(async (c) => {
			const place = { store: await c.get(store), space: devices, log: c.log, random: c.random };
			const records = recordsFor<StoredDevice>(place);
			return {
				nameOf: records.nameOf,
				save: records.named.create,
				read: records.named.read,
				update: records.named.change,
				walk: records.walk,
			};
		}),
		m.provide(userCodes).by(async (c) => {
			const place = { store: await c.get(store), space: codes, log: c.log, random: c.random };
			const records = recordsIn<string>(place);
			return { save: records.create, read: records.read };
		}),
		m.provide(placed).by(async (c) =>
			phasedRecordsIn<StoredApproval>(
				{
					store: await c.get(store),
					space: approvals,
					index: indexSpaceOf(approvals),
					log: c.log,
					random: c.random,
				},
				subjectRecordsPhase.once(await c.getOptional(storeControl)),
				"device-grant-store",
				c.refuse,
			),
		),
		// The builder's own ports, an approval created for its subject.
		m.provide(approvalRecords).by(async (c) => {
			const builder = await c.get(placed);
			return {
				create: builder.create,
				update: builder.change,
				erase: builder.erase,
				migrate: builder.migrate,
			};
		}),
		// Out of traffic until the phase reads: no call is judged on a phase not read.
		m.contribute(probes).by(async (c) => {
			const builder = await c.get(placed);
			return { name: "device-grant-store.phase", check: () => builder.ready() };
		}),
	],
);
