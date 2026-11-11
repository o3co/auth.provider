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
import type { Settings } from "../section.ts";
import {
	type FamilyStore,
	familyStore,
	type RedemptionStore,
	redemptionStore,
	type StoredFamily,
	type TokenFamilies,
	tokenFamilies,
} from "../store.ts";

export interface Stores {
	readonly families: FamilyStore;
	readonly redemptions: RedemptionStore;
	readonly tokenFamilies: TokenFamilies;
}

/** A family store's save seen without a subject: a store offering no `unowned` keeps no subject, and a mark holds none. */
type SaveUnowned = (id: string, record: StoredFamily, lifetimeMs: number) => Promise<string>;

export function settling(stores: Stores, tokens: Tokens, now: () => number, lifetimeMs: number) {
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
	// Revokes a family by its mark alone, which refuses every token of it from then. No record: gone by
	// its end, by its subject's erasure, or never founded, each read as ended. Until 0.22 a mark is still
	// saved there, for a 0.19 founder writing the redemption's link first; `closed` marks nothing.
	const revokeFamily = async (id: string) => {
		const revoked = toStored({ format: 1, revoked: true });
		const marked = await stores.families.update(id, () => ({ value: revoked }));
		if (marked) return;
		const written = stores.families.unowned
			? await stores.families.unowned(id, revoked, lifetimeMs)
			: await (stores.families.save as unknown as SaveUnowned)(id, revoked, lifetimeMs);
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
	const issuing = await c.get(tokens);
	// A round that fails once its access token is issued withdraws it; without a denylist it could not.
	if (!issuing.revocable()) {
		return c.refuse(
			"refresh",
			"refresh tokens cannot be handled where access tokens cannot be revoked",
		);
	}
	const lifetimeMs = c.section.lifetime * 1000;
	const revoker = settling(stores, issuing, c.clock.now, lifetimeMs);
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
