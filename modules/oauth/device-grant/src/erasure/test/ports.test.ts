import type { MigrationReport, SpaceReport } from "@mod/erasure-extensions";
import { expect, it } from "vitest";
import type { ApprovalRecords, DeviceStore } from "../../store.ts";
import { portsOf, portsRefused } from "../ports.ts";

const devices = { nameOf: (c: string) => c } as unknown as DeviceStore;
const approvals = { create: async () => "created" as const } as unknown as ApprovalRecords;
const erase = async () => ({}) as SpaceReport;
const migrate = async () => ({}) as MigrationReport;
const walk = async () => ({ kind: "walked" }) as const;

it("takes all three erasure ports or none, refusing a part", () => {
	expect(portsRefused({ devices, approvals })).toBeUndefined();
	expect(portsOf({ devices, approvals })).toBeUndefined();
	const whole = { devices: { ...devices, walk }, approvals: { ...approvals, erase, migrate } };
	expect(portsRefused(whole)).toBeUndefined();
	expect(portsOf(whole)).toBeDefined();
	for (const part of [
		{ devices: { ...devices, walk }, approvals },
		{ devices, approvals: { ...approvals, erase, migrate } },
		{ devices: { ...devices, walk }, approvals: { ...approvals, erase } },
	]) {
		expect(portsRefused(part)).toContain("all three, or none");
		expect(portsOf(part)).toBeUndefined();
	}
});

it("calls each port on its own place", async () => {
	const seen: unknown[] = [];
	const place = {
		...devices,
		walk: async function (this: unknown) {
			seen.push(this);
			return { kind: "walked" } as const;
		},
	};
	const ports = portsOf({ devices: place, approvals: { ...approvals, erase, migrate } });
	await ports?.devices.walk({} as never, () => true, new AbortController().signal);
	expect(seen).toEqual([place]);
});
