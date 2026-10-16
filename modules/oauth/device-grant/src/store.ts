import { contract } from "@mod/kernel";

declare const stored: unique symbol;
/** A device's record as the store keeps it: the store never reads it, and only device-grant opens it. */
export type StoredDevice = { readonly [stored]: true };

/** Where devices are kept, by a name made from the device code. Every call throws Unavailable when the store cannot tell. */
export interface DeviceStore {
	/** A device's name: never the device code, which cannot be had from it; names are kept, so it never changes. */
	nameOf(deviceCode: string): string;
	/** Keeps a new record for its lifetime, unless the name holds one already. */
	save(name: string, record: StoredDevice, lifetimeMs: number): Promise<"created" | "exists">;
	read(name: string): Promise<StoredDevice | undefined>;
	/** Changes the record from what it holds; `change` reruns on a race, and `before` is what the run that stands read. Nothing when gone. */
	update(
		name: string,
		change: (record: StoredDevice) => { readonly value: StoredDevice } | undefined,
	): Promise<{ readonly before: StoredDevice; readonly after: StoredDevice } | undefined>;
}

/** Which device (its name) a user code names, for as long as the device lives. */
export interface UserCodes {
	save(userCode: string, device: string, lifetimeMs: number): Promise<"created" | "exists">;
	read(userCode: string): Promise<string | undefined>;
}

export const deviceStore = contract<DeviceStore>("device-grant.device-store");
export const userCodes = contract<UserCodes>("device-grant.user-codes");

/**
 * An approval that was lost would leave a device waiting; one consumed that came back would issue
 * twice. The poll consumes before it issues, so that write confirms what it read.
 */
export const deviceStoreNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
	/** Names derive from the device code, so the store never keeps it in clear. */
	namesFromSecret: true,
} as const;
