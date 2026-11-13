import { createHash } from "node:crypto";
import { memoryRecords } from "@mod/records/testing";
import type {
	ApprovalRecords,
	DeviceStore,
	StoredApproval,
	StoredDevice,
	UserCodes,
} from "../src/store.ts";

/** A device's name as a store might make it: not the device code. */
const nameOf = (code: string) => `n.${createHash("sha256").update(code).digest("base64url")}`;

/** device-grant's store interfaces on the records stand-in, ending lifetimes on `clock`. */
export function recordsStandIn(clock: () => number) {
	const size = { shards: 1, perShard: 1 };
	const kept = memoryRecords<StoredDevice>(clock, size);
	const codes = memoryRecords<string>(clock, size);
	const devices: DeviceStore = {
		nameOf,
		save: kept.records.create,
		read: kept.records.read,
		update: kept.records.change,
	};
	const userCodes: UserCodes = { save: codes.records.create, read: codes.records.read };
	const approved = memoryRecords<StoredApproval>(clock, size);
	/** Subjects erased: no approval is created for them, as a Store fencing creation answers. */
	const erased = new Set<string>();
	const approvals: ApprovalRecords = {
		create: async (name, record, lifetimeMs, subject) =>
			erased.has(subject) ? "erased" : approved.records.create(name, record, lifetimeMs),
		read: approved.records.read,
	};
	return { devices, userCodes, approvals, erased, kept, approved };
}
