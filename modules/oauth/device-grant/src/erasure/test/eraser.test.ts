import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { describe, expect, it } from "vitest";
import type { ApprovalRecords, DeviceStore, DevicesWalked, StoredDevice } from "../../store.ts";
import { deviceGrantEraser } from "../eraser.ts";

const signal = new AbortController().signal;
const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const devices = { nameOf: (c: string) => c } as unknown as DeviceStore;
const approvals = { create: async () => "created" as const } as unknown as ApprovalRecords;
const device = (more: object = {}) =>
	({
		format: 2,
		clientId: "tv",
		scope: [],
		audience: [],
		expiresAt: 1,
		intervalMs: 5000,
		state: "approved",
		...more,
	}) as unknown as StoredDevice;
const legacy = { subject: "alice", approvedAt: 0, amr: [], authenticatedAt: 0 };

/** Stores offering every port: devices walking `held` (or answering `answer`), approvals noting each call. */
const erasing = (held: StoredDevice[], asked: string[], answer?: DevicesWalked) => ({
	devices: {
		...devices,
		walk: async (_w: Walk, visit: (r: StoredDevice) => Promise<boolean> | boolean) => {
			if (answer) return answer;
			for (const one of held) if (!(await visit(one))) return { kind: "stopped" } as const;
			return { kind: "walked" } as const;
		},
	},
	approvals: {
		...approvals,
		erase: async (subject: string) => {
			asked.push(`erase ${subject}`);
			return { kind: "fenced" } as unknown as SpaceReport;
		},
		migrate: async (_w: Walk, reading: SubjectReading) => {
			const read = await reading("n", {}).then(
				() => "read",
				() => "refused to read",
			);
			asked.push(`migrate, ${read}`);
			return { kind: "migrated", indexed: 0, removed: 0 } as unknown as MigrationReport;
		},
	},
});

describe("device-grant's eraser", () => {
	it("states that it cannot erase where the stores lack the ports, answering empty reports", async () => {
		const eraser = deviceGrantEraser({ devices, approvals });
		expect([eraser.name, eraser.erasable, eraser.after]).toEqual([
			"device-grant",
			false,
			undefined,
		]);
		expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
		expect(await eraser.migrate(walk, signal)).toEqual([]);
	});

	it("erases approvals by subject, each subject in a window, and migrates them reading none", async () => {
		const asked: string[] = [];
		const eraser = deviceGrantEraser(erasing([device({ state: "taken" })], asked));
		expect(eraser.erasable).toBe(true);
		expect((await eraser.online("alice", signal)).reports).toHaveLength(1);
		expect((await eraser.window(["bob", "carol"], walk, signal)).reports).toHaveLength(2);
		expect(await eraser.migrate(walk, signal)).toEqual([
			{ kind: "migrated", indexed: 0, removed: 0 },
		]);
		expect(asked).toEqual(["erase alice", "erase bob", "erase carol", "migrate, refused to read"]);
	});

	it("stops while a device record holds a 0.19 approval, giving the one bound to run again after", async () => {
		const eraser = deviceGrantEraser(erasing([device(), device({ approval: legacy })], []));
		const [, stop] = await eraser.migrate(walk, signal);
		expect(stop).toEqual({
			kind: "owner-stopped",
			reason: expect.stringContaining("0.19 instance kept"),
		});
		const reason = stop?.kind === "owner-stopped" ? stop.reason : "";
		expect(reason).toContain("7,200 s after the last 0.19 instance stopped");
		expect(reason).toContain("a 0.19 instance is still writing");
	});

	it("stops for a device record it cannot open, as one that may hold a subject", async () => {
		const eraser = deviceGrantEraser(erasing([device({ format: 9 })], []));
		const [, stop] = await eraser.migrate(walk, signal);
		expect(stop).toMatchObject({
			kind: "owner-stopped",
			reason: expect.stringContaining("another shape"),
		});
	});

	it("never reads a walk that did not finish as clean", async () => {
		for (const reason of ["walk-unsteady", "aborted", "unavailable"] as const) {
			const eraser = deviceGrantEraser(erasing([], [], { kind: "unfinished", reason }));
			const [, stop] = await eraser.migrate(walk, signal);
			expect(stop, reason).toMatchObject({
				kind: "owner-stopped",
				reason: expect.stringContaining(reason),
			});
		}
	});
});
