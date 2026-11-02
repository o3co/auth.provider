import { type BuildContext, type Log, Unavailable } from "@mod/kernel";
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
	issuedAccess,
	type MemberLists,
	type RedemptionStore,
	redemptionStore,
	type SettleList,
	sessionFamilies,
	settleList,
	type TokenFamilies,
	tokenFamilies,
} from "../store.ts";

export interface Stores {
	readonly families: FamilyStore;
	readonly redemptions: RedemptionStore;
	readonly sessionFamilies: MemberLists;
	readonly issuedAccess: MemberLists;
	readonly tokenFamilies: TokenFamilies;
	readonly settles: SettleList;
}

export function settling(
	stores: Stores,
	tokens: Tokens,
	log: Log,
	now: () => number,
	lifetimeMs: number,
) {
	const revokeMember = async (member: string) => {
		if ((await tokens.revokeReferenced(member)).kind === "unsupported") {
			throw new Unavailable("refresh");
		}
	};
	/** Remembers an access token the family issued; an eviction revokes what it dropped and fails. */
	const recordAccess = async (id: string, access: { id: string; expiresAt: number }) => {
		const remainingMs = access.expiresAt - now() + allowanceMs;
		const link = toStoredLink({ format: 1, family: id });
		// A link already there is this write's own, sent again, or a token id named twice.
		if ((await stores.tokenFamilies.save(access.id, link, remainingMs)) !== "created") {
			const kept = await stores.tokenFamilies.read(access.id);
			if (!kept || fromStoredLink(kept)?.family !== id) throw new Unavailable("refresh");
		}
		const { pushedOut } = await stores.issuedAccess.add(id, referenceOf(access), remainingMs);
		if (pushedOut.length > 0) {
			log.error("refresh.access_pushed_out", { count: pushedOut.length });
			// One whose revocation fails awaits, and its family's revocation revokes it.
			for (const member of pushedOut) {
				await revokeMember(member);
				await stores.issuedAccess.settled(id, member);
			}
			throw new Unavailable("refresh");
		}
	};
	/** The family's access tokens, those its cap pushed out and still awaiting among them. */
	const issuedBy = async (id: string) => [
		...(await stores.issuedAccess.members(id)).map(({ member }) => member),
		...(await stores.issuedAccess.awaiting(id)),
	];
	// Revokes a family and what it issued. Listed first, so `sweep` finishes one stopped halfway; the
	// mark is written even with no record, so a family being started now never comes alive.
	const revokeFamily = async (id: string) => {
		await stores.settles.add(id);
		const revoked = toStored({ format: 1, revoked: true });
		const marked = await stores.families.update(id, () => ({ value: revoked }));
		if (!marked) {
			// No record yet: the mark keeps a family being started now from ever coming alive.
			const written = await stores.families.save(id, revoked, lifetimeMs);
			// A family placed meanwhile is marked when the revocation is tried again.
			if (written !== "created") throw new Unavailable("refresh");
		}
		// Cleanup after the mark, which already refuses every token of the family: those its cap
		// pushed out too, each settled only once this pass revoked it.
		const gone = new Set<string>();
		for (const member of await issuedBy(id)) {
			await revokeMember(member);
			gone.add(member);
		}
		for (const member of await stores.issuedAccess.awaiting(id)) {
			if (gone.has(member)) await stores.issuedAccess.settled(id, member);
		}
		await stores.settles.done(id);
	};
	const sweep = async () => {
		const { failed } = await stores.settles.each(revokeFamily);
		if (failed > 0) log.warn("refresh.settle_retry_failed", { count: failed });
	};
	const revokeIssued = (access: { id: string; expiresAt: number }) =>
		revokeMember(referenceOf(access));
	return { recordAccess, revokeIssued, revokeFamily, sweep };
}

export type Revoker = ReturnType<typeof settling>;

/** What `settlingIn` takes, and so every factory built on it. */
export const settlingTakes = [
	familyStore,
	redemptionStore,
	sessionFamilies,
	issuedAccess,
	tokenFamilies,
	settleList,
	tokens,
];

/** The stores and the revoker over the contracts the assembly gives; refuses where access tokens cannot be revoked. */
export async function settlingIn(c: BuildContext<Settings>) {
	const stores: Stores = {
		families: await c.get(familyStore),
		redemptions: await c.get(redemptionStore),
		sessionFamilies: await c.get(sessionFamilies),
		issuedAccess: await c.get(issuedAccess),
		tokenFamilies: await c.get(tokenFamilies),
		settles: await c.get(settleList),
	};
	const issuing = await c.get(tokens);
	// Revoking a family must revoke what it issued; without a denylist it could not.
	if (!issuing.revocable()) {
		return c.refuse(
			"refresh",
			"refresh tokens cannot be handled where access tokens cannot be revoked",
		);
	}
	const lifetimeMs = c.section.lifetime * 1000;
	const revoker = settling(stores, issuing, c.log, c.clock.now, lifetimeMs);
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
			if (!live) {
				// The mark may stand over a revocation stopped halfway, its access tokens not yet revoked,
				// and names no client: finished before it is answered, whoever asks, as finishing twice is
				// harmless and an outage answers the same to every client.
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

/** session's closing of a session: every family it started. */
export async function participantOver(c: BuildContext<Settings>) {
	const { stores, revoker } = await settlingIn(c);
	return {
		name: "refresh",
		// Safe to repeat and to run on several hosts at once: revoking a family twice is harmless.
		closing: async (session: { readonly id: string }) => {
			for (const { member } of await stores.sessionFamilies.members(session.id)) {
				await revoker.revokeFamily(member);
			}
			// Those its cap pushed out whose revocation never got through: revoked here, then settled.
			for (const member of await stores.sessionFamilies.awaiting(session.id)) {
				await revoker.revokeFamily(member);
				await stores.sessionFamilies.settled(session.id, member);
			}
		},
	};
}
