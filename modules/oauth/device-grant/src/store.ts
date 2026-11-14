import type { MigrationReport, SpaceReport, SubjectReading, Walk } from "@mod/erasure-extensions";
import { contract } from "@mod/kernel";
import { approvalDriftMs, codeLifetimeMaxSeconds } from "./bounds.ts";

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
	/**
	 * Once, under the maintenance key: hands `visit` each device record a walk of the store meets,
	 * until `visit` answers false; optional in 0.20. TODO(0.22): goes with the 0.19 approval read
	 * (`grant/grant.ts`). `walked` when every record
	 * was handed over; `stopped` where `visit` stopped it; `unfinished` with why where the walk could
	 * not finish, which tells nothing of the records it did not reach. Its reads need no
	 * confirmation: 0.19's approval writes were confirmed and survive a failover, and 0.20 never
	 * removes one, so a record holding one is met; a new one appears only while a 0.19 instance
	 * still writes, which the stop's reason names.
	 */
	walk?(
		walk: Walk,
		visit: (record: StoredDevice) => Promise<boolean> | boolean,
		signal: AbortSignal,
	): Promise<DevicesWalked>;
}

/** A walk of the device records: all of them handed over, stopped by its visitor, or not finished. */
export type DevicesWalked =
	| { readonly kind: "walked" }
	| { readonly kind: "stopped" }
	| {
			readonly kind: "unfinished";
			readonly reason: "walk-unsteady" | "aborted" | "unavailable";
	  };

declare const approval: unique symbol;
/** An approval's record as the store keeps it: only device-grant opens it. */
export type StoredApproval = { readonly [approval]: true };

/**
 * Each device's approval, kept apart from the device under its approving subject, by the device's
 * name. Every call throws Unavailable when the store cannot tell.
 */
export interface ApprovalRecords {
	/**
	 * Keeps a new approval for its lifetime and its subject, unless the name holds one already
	 * (`exists`) or, where the Store fences creation past a subject's erasure, the subject is erased
	 * there (`erased`).
	 */
	create(
		name: string,
		record: StoredApproval,
		lifetimeMs: number,
		subject: string,
	): Promise<"created" | "exists" | "erased">;
	/**
	 * Changes the approval from what it holds; `change` reruns on a race, so it is pure. Nothing when
	 * gone. Its answer is confirmed, a rewrite that writes nothing and an absence included: the poll
	 * reads an approval so.
	 */
	update(
		name: string,
		change: (record: StoredApproval) => { readonly value: StoredApproval } | undefined,
	): Promise<{ readonly before: StoredApproval; readonly after: StoredApproval } | undefined>;
	/**
	 * Erases a subject's approvals here, where the Store can: optional in 0.20, required in 0.22.
	 * In 0.20, with the devices' `walk`, all three or none.
	 */
	erase?(subject: string, signal: AbortSignal): Promise<SpaceReport>;
	/** Once, under the maintenance key; optional as `erase` is. */
	migrate?(walk: Walk, reading: SubjectReading, signal: AbortSignal): Promise<MigrationReport>;
}

/** Which device (its name) a user code names, for as long as the device lives. */
export interface UserCodes {
	save(userCode: string, device: string, lifetimeMs: number): Promise<"created" | "exists">;
	read(userCode: string): Promise<string | undefined>;
}

export const deviceStore = contract<DeviceStore>("device-grant.device-store");
export const approvalRecords = contract<ApprovalRecords>("device-grant.approvals");

/**
 * The longest an approval is kept: `code-lifetime`'s longest, 3600 s, as an approval is needed
 * only while its device lives, and 120 s for clock drift between hosts.
 */
export const approvalRecordMaxMs = codeLifetimeMaxSeconds * 1000 + approvalDriftMs;

/** A lost approval would leave its approved device waiting to its end; one kept past it, nothing. */
export const approvalRecordsNeeds = {
	neverEvicted: true,
	survivesCrash: true,
	survivesFailover: true,
} as const;
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
