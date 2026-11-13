// Frozen from v0.19.1, modules/oauth/device-grant/src/record.ts (the record's shapes and read) and
// src/grant/grant.ts (a poll's decision, and its take): how a 0.19.x instance reads and polls a
// device, for the mixed-fleet tests. Never updated with device-grant's own; deleted at 0.22.
import { z } from "zod";
import type { DeviceStore, StoredDevice } from "../src/store.ts";

const strings = z.array(z.string());
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
type Device0191 = z.infer<typeof shape>;

/** v0.19.1's read of a kept device: none for a format or shape it does not know. */
export const readAt0191 = (stored: StoredDevice | undefined): Device0191 | undefined => {
	const read = shapes.safeParse(stored);
	return read.success ? ({ ...read.data, format: 2 } as Device0191) : undefined;
};

const polled = (device: Device0191, clientId: string, now: number) => {
	if (device.clientId !== clientId || device.state === "taken") return { answer: "not-yours" };
	if (device.expiresAt <= now) return { answer: "expired" };
	const seen = { ...device, lastPollAt: now };
	if (device.lastPollAt !== undefined && now - device.lastPollAt < device.intervalMs) {
		return { answer: "poll-too-soon", left: { ...seen, intervalMs: device.intervalMs + 5000 } };
	}
	switch (device.state) {
		case "pending":
			return { answer: "pending", left: seen };
		case "approved":
			return { answer: "issue", left: { ...seen, state: "taken" as const } };
		case "denied":
			return { answer: "denied", left: { ...seen, state: "taken" as const } };
	}
};

/** v0.19.1's poll, up to what it would issue from: `issue` with the approval on the record, else its error. */
export async function pollAt0191(
	devices: DeviceStore,
	name: string,
	clientId: string,
	now: number,
) {
	const changed = await devices.update(name, (stored) => {
		const held = readAt0191(stored);
		const left = held && polled(held, clientId, now).left;
		return left && { value: left as unknown as StoredDevice };
	});
	const before = readAt0191(changed?.before);
	if (!before) return "invalid_grant";
	const { answer } = polled(before, clientId, now);
	if (answer !== "issue") return answer;
	return before.approval ? "issue" : "invalid_grant";
}
