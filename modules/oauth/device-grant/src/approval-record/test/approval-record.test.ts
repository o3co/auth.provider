import { isUnavailable } from "@mod/kernel";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import type { Approval } from "../../record.ts";
import type { ApprovalRecords, StoredApproval } from "../../store.ts";
import { approvalOf, createApproval } from "../approval-record.ts";

const approval: Approval = {
	subject: "alice",
	approvedAt: 1000,
	amr: ["pwd"],
	authenticatedAt: 900,
	session: "s-1",
};

const placed = () => {
	let now = 0;
	const { records } = memoryRecords<StoredApproval>(() => now, { shards: 1, perShard: 1 });
	const lifetimes: number[] = [];
	const subjects: string[] = [];
	const approvals: ApprovalRecords = {
		create: async (name, record, ms, subject) => {
			lifetimes.push(ms);
			subjects.push(subject);
			return records.create(name, record, ms);
		},
		read: records.read,
	};
	return { approvals, records, lifetimes, subjects, advance: (ms: number) => (now += ms) };
};

it("keeps an approval for its subject until its device ends and two minutes after, and reads it back", async () => {
	const p = placed();
	expect(await createApproval(p.approvals, "n-1", approval, 61_000, 1000)).toBe("created");
	expect([p.lifetimes, p.subjects]).toEqual([[180_000], ["alice"]]);
	expect(await approvalOf(p.approvals, "n-1")).toEqual(approval);
	expect(
		await createApproval(p.approvals, "n-1", { ...approval, subject: "bob" }, 61_000, 1000),
	).toBe("exists");
	expect(await approvalOf(p.approvals, "n-1")).toEqual(approval);
	expect(await approvalOf(p.approvals, "n-2")).toBeUndefined();
});

it("keeps an approval at least a millisecond, past its device's end too", async () => {
	const p = placed();
	await createApproval(p.approvals, "n-1", approval, 0, 500_000);
	expect(p.lifetimes).toEqual([1]);
});

it("reads an approval of another format or shape as one it cannot read, never as none", async () => {
	const p = placed();
	for (const [name, odd] of [
		["n-1", { format: 2, ...approval }],
		["n-2", { format: 1, ...approval, extra: 1 }],
		["n-3", { format: 1, subject: "alice" }],
	] as const) {
		await p.records.create(name, odd as unknown as StoredApproval, 60_000);
		await expect(approvalOf(p.approvals, name)).rejects.toSatisfy(isUnavailable);
	}
});
