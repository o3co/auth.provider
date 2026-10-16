import type { Runtime } from "@mod/kernel";
import { z } from "zod";
import type { DeviceStore, StoredDevice } from "./store.ts";

export interface Approval {
	readonly subject: string;
	/** On `kernel`'s clock, epoch ms. */
	readonly approvedAt: number;
	readonly amr: readonly string[];
	readonly authenticatedAt: number;
	/** The authentication time is not known, so no token issued from the approval states one. */
	readonly authenticatedAtUnknown?: true;
	/** The approving session's handle, which the issuance policies are asked with. */
	readonly session?: string;
}

/** A device from its authorization to the poll that takes its answer. */
export interface Device {
	/** The record's format; one of format 1 is read too, its approval's time known. */
	readonly format: 2;
	readonly clientId: string;
	readonly scope: readonly string[];
	readonly audience: readonly string[];
	/** On `kernel`'s clock, epoch ms. */
	readonly expiresAt: number;
	readonly intervalMs: number;
	readonly lastPollAt?: number;
	readonly state: "pending" | "approved" | "denied" | "taken";
	readonly approval?: Approval;
}

const strings = z.array(z.string());
/** Epoch ms that a Date can hold, so a time read back can be written out again. */
const time = z.number().min(0).max(8.64e15);
const approvalBefore = z.strictObject({
	subject: z.string(),
	approvedAt: time,
	amr: strings,
	authenticatedAt: time,
	session: z.string().optional(),
});
const shapeBefore = z.strictObject({
	format: z.literal(1),
	clientId: z.string(),
	scope: strings,
	audience: strings,
	expiresAt: time,
	intervalMs: z.number(),
	lastPollAt: time.optional(),
	state: z.enum(["pending", "approved", "denied", "taken"]),
	approval: approvalBefore.optional(),
});
const shape = shapeBefore.extend({
	format: z.literal(2),
	approval: approvalBefore
		.extend({ authenticatedAtUnknown: z.literal(true).optional() })
		.optional(),
});
const shapes = z.union([shape, shapeBefore]);

export const toStored = (device: Device) => device as unknown as StoredDevice;
/** What a kept record holds, checked on every read; nothing for a format or shape this does not know. */
export const fromStored = (stored: StoredDevice | undefined): Device | undefined => {
	// safeParse lets a field's own throw through; a record that throws when read is no record.
	try {
		const read = shapes.safeParse(stored);
		return read.success ? ({ ...read.data, format: 2 } as Device) : undefined;
	} catch {
		return undefined;
	}
};

/** Rewrites a device, each run on the clock it reads; answers the record and time the run that stands read. */
export async function rewriteAt(
	devices: DeviceStore,
	name: string,
	clock: Runtime["clock"],
	decide: (held: Device, at: number) => Device | undefined,
): Promise<{ readonly before: Device; readonly at: number } | undefined> {
	let at = 0;
	const changed = await devices.update(name, (stored) => {
		at = clock.now();
		const held = fromStored(stored);
		const left = held && decide(held, at);
		return left && { value: toStored(left) };
	});
	const before = fromStored(changed?.before);
	return before && { before, at };
}
