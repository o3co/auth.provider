import { createHash } from "node:crypto";
import { type Command, keysOf, type Match, storeRead, storeWrite } from "@mod/conformance/testing";
import type { Device } from "./faults.ts";

// The store's own names a scene matches its writes by: the space, its records' names and fields, and
// the operations, as device-grant-store and records keep them. Nothing else in the area names them.

/** The deployment's `redis.prefix`: the adapter's own, as no scene sets one. */
export const prefix = "store";
const devices = "device-grant-store.devices";

/** Whether a command is a store call: the adapter sends each as a script. */
export const isStoreCall = (command: Command) => command.name === "EVAL";

/** The device's record's partition: its name, made from the device code as device-grant-store's records make it. */
const partitionOf = (d: Device) =>
	`1.${createHash("sha256").update(`${devices}\n${d.deviceCode}`).digest("base64url")}`;

/** A device's record as the store holds it: the fields a scene tells its writes by. */
interface DeviceRecord {
	readonly state?: unknown;
	readonly approval?: unknown;
}
const recordWrite = (d: Device, is: (r: DeviceRecord) => boolean): Match =>
	storeWrite({
		prefix,
		space: devices,
		partition: partitionOf(d),
		name: "record",
		operations: ["replaceIf"],
		value: (v) => is(v as DeviceRecord),
	});

/** The poll's write that takes the approval, before any token is made. */
export const takeOf = (d: Device) =>
	recordWrite(d, (r) => r.state === "taken" && r.approval !== undefined);

/** The write that decides the device: approved, with alice's approval, or denied. */
export const decisionOf = (d: Device, state: "approved" | "denied") =>
	recordWrite(d, (r) => r.state === state);

/**
 * The write a rewrite sends where what it read leaves nothing to write: it confirms the record still
 * holds what was read, or that none is there, so it tells no kept record from a lost one.
 */
export const confirmedOf = (d: Device): Match =>
	storeWrite({
		prefix,
		space: devices,
		partition: partitionOf(d),
		name: "settled",
		operations: ["batch"],
	});

/**
 * The writes of a subject's revocation boundary: its record created, or written from what it holds; not
 * the mark that confirms, before the first, that the subject holds none.
 */
export const boundaryOf = (subject: string): Match =>
	storeWrite({
		prefix,
		space: "subject-revocation-store.boundaries",
		partition: subject,
		operations: ["putIfAbsent", "replaceIf"],
	});

/** The write that creates a subject's first boundary; a revocation that finds one held writes it from that instead. */
export const boundaryCreated = (subject: string): Match =>
	storeWrite({
		prefix,
		space: "subject-revocation-store.boundaries",
		partition: subject,
		operations: ["putIfAbsent"],
	});

/**
 * A follower's first write after a revocation's boundary: session-lifecycle adding the subject's
 * sessions to its closings, before it closes any.
 */
export const closingAdded: Match = storeWrite({ prefix, space: "session-store.closings" });

/** A read of the device's record, as the decision makes one first. */
export const recordReadOf = (d: Device): Match => {
	const read = storeRead({ prefix, space: devices, name: "record" });
	return {
		request: (command) =>
			read.request(command) && keysOf(command).some((k) => k.partition === partitionOf(d)),
		succeeded: read.succeeded,
	};
};
