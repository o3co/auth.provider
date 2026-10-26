import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import type { RedemptionHook } from "@mod/code-grant";
import type { TokenTie } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import type { ClaimsSelections, Issued, Selection, SelectionConsent, Target } from "./contract.ts";
import type { SelectionRecords, StoredSelection } from "./store.ts";
import { holds, read, stored, withinLimits } from "./stored.ts";

/** A code's selection outlives the code by this much, so a code still alive finds it. */
const codeMarginMs = 60_000;
/** A pin holds a redemption's selection this long: one exchange, never a deadline it enforces. */
const pinHoldMs = 300_000;
/** A token's selection outlives the token by this much, for clock drift between hosts. */
const tokenAllowanceMs = 120_000;

const nameOf = {
	code: (redemption: string) => `c.${redemption}`,
	pin: (redemption: string) => `p.${redemption}`,
	family: (familyId: string) => `f.${familyId}`,
	token: (tokenId: string) => `t.${tokenId}`,
};

export function selectionsWith(parts: {
	readonly records: SelectionRecords;
	/** Whoever judges consent; with none, no name is agreed to. */
	readonly consent: SelectionConsent | undefined;
	readonly now: () => number;
}) {
	const { records, consent, now } = parts;
	/** Keeps a record once; a name already holding one keeps the first. */
	const save = async (name: string, value: StoredSelection, lifetimeMs: number) => {
		await records.save(name, value, Math.max(1, lifetimeMs));
	};
	const agreed = async (client: Client, subject: string, scope: string) =>
		clientAllowance.allowsScope(client, scope) &&
		(consent ? await consent.consented(client, subject, scope) : false);
	/** The target with only the names allowed and agreed to now; its constraints kept, since they only hold back. */
	const cut = async (client: Client, subject: string, target: Target): Promise<Target> => {
		const names = [];
		for (const named of target.names) {
			if (await agreed(client, subject, named.scope)) names.push(named);
		}
		return { names, constraints: target.constraints };
	};
	const bounded = (asked: Selection) => {
		if (!withinLimits(asked)) throw new TypeError("claims-selection: a selection past its bounds");
	};
	const pinned = async (redemption: string) => {
		const kept = await records.read(nameOf.pin(redemption));
		// A pin gone holds nothing back any more: the redemption fails rather than release unconstrained.
		if (kept === undefined) throw new Unavailable("claims-selection");
		return read.pin(kept);
	};
	const keepForToken = async (access: Issued, target: Target) => {
		if (!holds(target)) return;
		await save(
			nameOf.token(access.id),
			stored.target(target),
			access.expiresAt - now() + tokenAllowanceMs,
		);
	};
	const forToken = async (tokenId: string) => {
		const kept = await records.read(nameOf.token(tokenId));
		return kept === undefined ? undefined : read.target(kept);
	};
	const selections: ClaimsSelections = {
		select: async (client, subject, asked) => {
			bounded(asked);
			return {
				idToken: await cut(client, subject, asked.idToken),
				userinfo: await cut(client, subject, asked.userinfo),
			};
		},
		keepForCode: async (redemption, selection, lifetimeMs) => {
			bounded(selection);
			if (!holds(selection.idToken) && !holds(selection.userinfo)) return;
			const saved = await records.save(
				nameOf.code(redemption),
				stored.code(selection),
				lifetimeMs + codeMarginMs,
			);
			// A code's name is made fresh for it: one already kept is not this code's.
			if (saved !== "created") throw new Unavailable("claims-selection");
		},
		forCode: pinned,
		forToken,
		follow: async (redemption, familyId, lifetimeMs) => {
			const selection = await pinned(redemption);
			if (!selection || !holds(selection.userinfo)) return;
			await save(nameOf.family(familyId), stored.target(selection.userinfo), lifetimeMs);
		},
		forRefreshed: async (familyId, client, subject, access) => {
			const kept = await records.read(nameOf.family(familyId));
			if (kept === undefined) return;
			await keepForToken(access, await cut(client, subject, read.target(kept)));
		},
	};
	const hook: RedemptionHook = {
		name: "claims-selection",
		pin: async (redemption) => {
			const kept = await records.read(nameOf.code(redemption));
			await save(
				nameOf.pin(redemption),
				stored.pin(kept === undefined ? undefined : read.code(kept)),
				pinHoldMs,
			);
		},
		redeemed: async (redeemed) => {
			const selection = await pinned(redeemed.redemption);
			if (selection) await keepForToken(redeemed.access, selection.userinfo);
		},
	};
	const tie: TokenTie = {
		name: "claims-selection",
		tieOf: async (tokenId) => {
			const target = await forToken(tokenId);
			if (!target || target.constraints.length === 0) return { kind: "none" };
			// An exchanged token keeps the constraints only: its names were never asked of its client.
			const constraints = target.constraints;
			return {
				kind: "held",
				join: async (issued) => {
					await keepForToken(issued, { names: [], constraints });
					return true;
				},
			};
		},
	};
	return { selections, hook, tie };
}
