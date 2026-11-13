import { Unavailable } from "@mod/kernel";
import { z } from "zod";
import type { Approval } from "../record.ts";
import type { ApprovalRecords, StoredApproval } from "../store.ts";

/** An approval outlives its device by this much, for clock drift between hosts. */
const driftMs = 120_000;

const time = z.number().min(0).max(8.64e15);
/** An approval as it is kept, in its own record: format 1. */
const shape = z.strictObject({
	format: z.literal(1),
	subject: z.string(),
	approvedAt: time,
	amr: z.array(z.string()),
	authenticatedAt: time,
	authenticatedAtUnknown: z.literal(true).optional(),
	session: z.string().optional(),
});

const toStored = (approval: Approval) => ({ format: 1, ...approval }) as unknown as StoredApproval;

/** What a kept approval holds; one of another format or shape is a record it cannot read. */
const fromStored = (stored: StoredApproval): Approval => {
	const read = shape.safeParse(stored);
	// Never taken for none: a device whose approval cannot be read waits, and is never issued.
	if (!read.success) throw new Unavailable("device-grant: an approval it cannot read");
	const { format: _, ...approval } = read.data;
	return approval as Approval;
};

/**
 * Keeps a device's approval, by the device's name, for its subject, until the device ends and the
 * drift after; `exists` where the name holds one, `erased` where the subject is erased.
 */
export const createApproval = (
	approvals: ApprovalRecords,
	name: string,
	approval: Approval,
	deviceEndsAt: number,
	now: number,
) =>
	approvals.create(
		name,
		toStored(approval),
		Math.max(1, deviceEndsAt - now + driftMs),
		approval.subject,
	);

/** The approval kept for a device, or none. */
export const approvalOf = async (approvals: ApprovalRecords, name: string) => {
	const stored = await approvals.read(name);
	return stored === undefined ? undefined : fromStored(stored);
};
