import { type BuildContext, Unavailable } from "@mod/kernel";
import { referenceOf, type Tokens, tokens } from "@mod/tokens";
import {
	allowanceMs,
	fromStored,
	fromStoredLink,
	liveOf,
	parseToken,
	toStored,
	toStoredLink,
} from "../record.ts";
import { familyLifetimeMaxMs, type Settings } from "../section.ts";
import {
	type FamilyStore,
	familyStore,
	type RedemptionStore,
	redemptionStore,
	type StoredFamily,
	type TokenFamilies,
	tokenFamilies,
} from "../store.ts";
import { portsOf, portsRefused } from "./ports.ts";

export interface Stores {
	readonly families: FamilyStore;
	readonly redemptions: RedemptionStore;
	readonly tokenFamilies: TokenFamilies;
}

type SaveUnowned = (id: string, record: StoredFamily, lifetimeMs: number) => Promise<string>;

/**
 * refresh's view of the family store's `save` with no subject, as before 0.20, for a mark holds none:
 * a type over the same method, never one an implementation writes; on a store with none of its ports.
 */
const unownedSave =
	(families: FamilyStore): SaveUnowned =>
	(id, record, lifetimeMs) =>
		(families.save as unknown as SaveUnowned).call(families, id, record, lifetimeMs);

/**
 * How long a mark with no record is kept: the longest a family may live, and an allowance, so a 0.19
 * founder whose link's reply was lost, resuming within it, finds the mark and founds nothing.
 */
const markMs = familyLifetimeMaxMs + allowanceMs;

export function settling(stores: Stores, tokens: Tokens, now: () => number) {
	/** Ties an access token to the family that issued it, so the family's mark refuses it. */
	const recordAccess = async (id: string, access: { id: string; expiresAt: number }) => {
		const remainingMs = access.expiresAt - now() + allowanceMs;
		const link = toStoredLink({ format: 1, family: id });
		// A link already there is this write's own, sent again, or a token id named twice.
		if ((await stores.tokenFamilies.save(access.id, link, remainingMs)) !== "created") {
			const kept = await stores.tokenFamilies.read(access.id);
			if (!kept || fromStoredLink(kept)?.family !== id) throw new Unavailable("refresh");
		}
	};
	// Through the store's `unowned` where it offers the ports, else its `save` with no subject (0.19's).
	const saveMark = portsOf(stores.families)?.unowned ?? unownedSave(stores.families);
	// Revokes a family by its mark alone, which refuses every token of it from then. No record: gone by
	// its end, by its subject's erasure, or never founded, each read as ended. Until 0.22 a mark is still
	// saved there, for a 0.19 founder writing the redemption's link first; `closed`, the space indexed,
	// marks nothing.
	const revokeFamily = async (id: string) => {
		const revoked = toStored({ format: 1, revoked: true });
		const marked = await stores.families.update(id, () => ({ value: revoked }));
		if (marked) return;
		const written = await saveMark(id, revoked, markMs);
		// A family placed meanwhile is marked when the revocation is tried again.
		if (written !== "created" && written !== "closed") throw new Unavailable("refresh");
	};
	/** Withdraws one access token issued in a round that then failed, so no one is handed it. */
	const revokeIssued = async (access: { id: string; expiresAt: number }) => {
		if ((await tokens.revokeReferenced(referenceOf(access))).kind === "unsupported") {
			throw new Unavailable("refresh");
		}
	};
	return { recordAccess, revokeIssued, revokeFamily };
}

export type Revoker = ReturnType<typeof settling>;

/** What `settlingIn` takes, and so every factory built on it. */
export const settlingTakes = [familyStore, redemptionStore, tokenFamilies, tokens];

/** The stores and the revoker over the contracts the assembly gives; refuses where access tokens cannot be revoked. */
export async function settlingIn(c: BuildContext<Settings>) {
	const stores: Stores = {
		families: await c.get(familyStore),
		redemptions: await c.get(redemptionStore),
		tokenFamilies: await c.get(tokenFamilies),
	};
	const ports = portsRefused(stores.families);
	if (ports !== undefined) return c.refuse("refresh", ports);
	const issuing = await c.get(tokens);
	// A round that fails once its access token is issued withdraws it; without a denylist it could not.
	if (!issuing.revocable()) {
		return c.refuse(
			"refresh",
			"refresh tokens cannot be handled where access tokens cannot be revoked",
		);
	}
	const lifetimeMs = c.section.lifetime * 1000;
	const revoker = settling(stores, issuing, c.clock.now);
	return { stores, revoker, lifetimeMs };
}

/** token-control's revocation of a refresh token: its whole family, for the client it was issued to. */
export async function revocableOver(c: BuildContext<Settings>) {
	const { stores, revoker } = await settlingIn(c);
	return {
		hint: "refresh_token",
		revoke: async (token: string, client: { readonly id: string }) => {
			const parsed = parseToken(token);
			if (!parsed) return "unknown" as const;
			const kept = fromStored(await stores.families.read(parsed.id));
			if (!kept) return "unknown" as const;
			const live = liveOf(kept);
			// Marked already, the mark is written again, confirmed, before it is answered: one read before its
			// write was confirmed could be lost in a failover. It names no client, so it is answered alike to all.
			if (!live) {
				await revoker.revokeFamily(parsed.id);
				return "done" as const;
			}
			// Another client's token is left alone but answered the same, so it learns nothing.
			if (live.clientId !== client.id) return "done" as const;
			await revoker.revokeFamily(parsed.id);
			return "written" as const;
		},
	};
}
