import type { ApprovalRecords, DeviceStore } from "../store.ts";

/** The two places device-grant keeps or checks a subject's data in. */
export interface ErasableStores {
	readonly devices: DeviceStore;
	readonly approvals: ApprovalRecords;
}

/** The places' erasure ports, offered whole, each called on its place. */
export interface StorePorts {
	readonly approvals: Required<Pick<ApprovalRecords, "erase" | "migrate">>;
	readonly devices: Required<Pick<DeviceStore, "walk">>;
}

const portsIn = (stores: ErasableStores) => [
	stores.approvals.erase,
	stores.approvals.migrate,
	stores.devices.walk,
];

/** Why the stores' ports cannot be used, or none: the one statement of the set, as the card gives it. */
export function portsRefused(stores: ErasableStores): string | undefined {
	const offered = portsIn(stores).filter((port) => port !== undefined).length;
	if (offered === 0 || offered === 3) return undefined;
	return "the approvals' erase and migrate and the devices' walk come together: all three, or none";
}

/** The set, where the stores offer it whole; none otherwise, `portsRefused` refusing a part at build. */
export function portsOf(stores: ErasableStores): StorePorts | undefined {
	const { approvals, devices } = stores;
	if (!approvals.erase || !approvals.migrate || !devices.walk) return undefined;
	const [erase, migrate, walk] = [approvals.erase, approvals.migrate, devices.walk];
	// Called on each place, so an implementation keeps its own `this`.
	return {
		approvals: {
			erase: (subject, signal) => erase.call(approvals, subject, signal),
			migrate: (w, reading, signal) => migrate.call(approvals, w, reading, signal),
		},
		devices: { walk: (w, visit, signal) => walk.call(devices, w, visit, signal) },
	};
}
