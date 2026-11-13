import { z } from "zod";
import {
	type RedemptionRecords,
	type StoredRedemptionRecord,
	storedRecordMaxMs,
} from "../store.ts";

/** What a redemption keeps: its token, once noted, and whether a reuse voided it. */
export interface RedemptionRecord {
	readonly format: 1;
	readonly token?: { readonly reference: string; readonly expiresAt: number };
	readonly void?: true;
}

const recordShape = z.strictObject({
	format: z.literal(1),
	token: z.strictObject({ reference: z.string(), expiresAt: z.number() }).optional(),
	void: z.literal(true).optional(),
});

/** A redemption record as the store keeps it; only code-grant reads what it holds. */
export const toStoredRedemptionRecord = (record: RedemptionRecord) =>
	record as unknown as StoredRedemptionRecord;
/** A stored value's redemption record, checked on every read; nothing for another shape. */
export const fromStoredRedemptionRecord = (
	stored: StoredRedemptionRecord | undefined,
): RedemptionRecord | undefined => {
	const read = recordShape.safeParse(stored);
	return read.success ? (read.data as RedemptionRecord) : undefined;
};

/** A redemption record outlives its token by this much, for clock drift between hosts. */
const allowanceMs = 120_000;

/**
 * Creates a redemption record for its subject, for `storedRecordMaxMs`, reading the clock before the
 * write: the record ends no earlier than that read and `storedRecordMaxMs`, so its token, ending by
 * `tokenEnd`, ends at least the allowance before it.
 */
export const createRedemptionRecord = async (
	records: RedemptionRecords,
	name: string,
	subject: string,
	now: () => number,
): Promise<{ readonly made: "created" | "exists" | "erased"; readonly tokenEnd: number }> => {
	const created = now();
	const made = await records.create(
		name,
		toStoredRedemptionRecord({ format: 1 }),
		storedRecordMaxMs,
		subject,
	);
	return { made, tokenEnd: created + storedRecordMaxMs - allowanceMs };
};

/** Whether a redemption record is kept under the name: the code was redeemed, whatever became of it. */
export const isRedeemed = async (records: RedemptionRecords, name: string): Promise<boolean> =>
	(await records.read(name)) !== undefined;

/** Notes the token on the record, which keeps its end; nothing where the record is gone. */
export const noteToken = async (
	records: RedemptionRecords,
	name: string,
	token: NonNullable<RedemptionRecord["token"]>,
): Promise<RedemptionRecord | undefined> => {
	const noted = await records.update(name, (stored) => {
		const r = fromStoredRedemptionRecord(stored);
		return r && { value: toStoredRedemptionRecord({ ...r, token }) };
	});
	return fromStoredRedemptionRecord(noted?.after);
};

/** Marks the record void, even if it is already; nothing where it is gone. */
export const markVoid = async (
	records: RedemptionRecords,
	name: string,
): Promise<RedemptionRecord | undefined> => {
	const marked = await records.update(name, (stored) => {
		const r = fromStoredRedemptionRecord(stored);
		return r && { value: toStoredRedemptionRecord({ ...r, void: true }) };
	});
	return fromStoredRedemptionRecord(marked?.after);
};
