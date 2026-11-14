import { type Eraser, ownerStopped, type SubjectReading } from "@mod/erasure-extensions";
import { fromStored } from "../record.ts";
import type { StoredDevice } from "../store.ts";
import { type ErasableStores, portsOf } from "./ports.ts";

/**
 * Frozen from v0.19.1 (tag v0.19.1): `code-lifetime` is at most 3600 s
 * (`modules/oauth/device-grant/src/section.ts`), and a device's record is kept twice its lifetime
 * (`modules/oauth/device-grant/src/authorization/authorization.ts`), an approval on it as long. So
 * a 0.19 approval's subject is gone from the devices this long after the last 0.19 instance stopped.
 */
const legacyBoundSeconds = 3600 * 2;

const rerun = `run again ${legacyBoundSeconds.toLocaleString("en")} s after the last 0.19 instance stopped, and if it persists past that, a 0.19 instance is still writing`;

/** Approvals are bounded: a migration indexes none, and reads none; one asked to read is a defect. */
const noneRead: SubjectReading = async () => {
	throw new Error("device-grant: approvals are bounded, so no migration reads one");
};

/** Why a device record stops the migration, or none for one that holds no subject. */
const heldIn = (stored: StoredDevice): string | undefined => {
	const device = fromStored(stored);
	if (!device) return `a device record of another shape, which may hold a subject; ${rerun}`;
	if (device.approval)
		return `a device record a 0.19 instance kept with its approval's subject; ${rerun}`;
	return undefined;
};

/**
 * device-grant's eraser, `device-grant`, as its approvals' space's `erasedBy` names it: a subject's
 * approvals erased through the store's own ports, and the devices checked for a 0.19 approval.
 * `erasable` only where the stores offer the set whole; where not, it answers empty reports.
 */
export function deviceGrantEraser(stores: ErasableStores): Eraser {
	const ports = portsOf(stores);
	if (!ports) {
		const none = { reports: [], logoutGaps: 0 };
		return {
			name: "device-grant",
			erasable: false,
			online: async () => none,
			window: async () => none,
			migrate: async () => [],
		};
	}
	const online = async (subject: string, signal: AbortSignal) => ({
		reports: [await ports.approvals.erase(subject, signal)],
		logoutGaps: 0,
	});
	return {
		name: "device-grant",
		erasable: true,
		online,
		// Bounded: no walk reaches an approval the fence does not, so a window fences each subject.
		window: async (subjects, _walk, signal) => {
			const reports = [];
			for (const subject of subjects) reports.push(...(await online(subject, signal)).reports);
			return { reports, logoutGaps: 0 };
		},
		migrate: async (walk, signal) => {
			const approvals = await ports.approvals.migrate(walk, noneRead, signal);
			// TODO(0.22): goes with the 0.19 approval read (`grant/grant.ts`), and the devices' walk with it.
			// The devices space holds no subject from 0.20, but a 0.19 approval stays on its record:
			// 0.20 never removes one. The owner's stop for a part subject-records does not read.
			let held = "";
			const walked = await ports.devices.walk(
				walk,
				(stored) => {
					held = heldIn(stored) ?? "";
					return held === "";
				},
				signal,
			);
			if (walked.kind === "walked") return [approvals];
			if (walked.kind === "stopped") return [approvals, ownerStopped(held)];
			// A walk that did not finish proves nothing of the records it did not reach.
			return [
				approvals,
				ownerStopped(`the device records' walk did not finish (${walked.reason}); run again`),
			];
		},
	};
}
