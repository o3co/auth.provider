import { createHash } from "node:crypto";
import { memoryRecords } from "@mod/records/testing";
import type { DeviceStore, StoredDevice, UserCodes } from "../src/store.ts";

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
	return { devices, userCodes, kept };
}
