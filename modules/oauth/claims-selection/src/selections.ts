import { clientAllowance } from "@mod/client-allowance";
import type { Client } from "@mod/clients";
import type { RedemptionHook } from "@mod/code-grant";
import type { TokenTie } from "@mod/grants";
import { Unavailable } from "@mod/kernel";
import type {
	ClaimScopes,
	ClaimsSelections,
	Issued,
	Selection,
	SelectionConsent,
	Target,
} from "./contract.ts";
import type { SelectionRecords, StoredSelection } from "./store.ts";
import { holds, nameOf, read, stored, withinLimits } from "./stored.ts";

/** A code's selection outlives the code by this much, so a code still alive finds it. */
const codeMarginMs = 60_000;
/** A pin holds a redemption's selection this long: one exchange, never a deadline it enforces. */
const pinHoldMs = 300_000;
/** A token's selection outlives the token by this much, for clock drift between hosts. */
const tokenAllowanceMs = 120_000;

export function selectionsWith(parts: {
	readonly records: SelectionRecords;
	/** Whoever judges consent; with none, no name is agreed to. */
	readonly consent: SelectionConsent | undefined;
	/** The table of claim scopes; with none, no claim has a scope. */
	readonly scopes: ClaimScopes | undefined;
	readonly now: () => number;
}) {
	const { records, consent, scopes, now } = parts;
	/** Keeps a record once for its subject, a name already holding one keeping the first. */
	const write = (name: string, value: StoredSelection, lifetimeMs: number, subject: string) =>
		records.create(name, value, Math.max(1, lifetimeMs), subject);
	/** A subject a caller past the types left out is its bug: nothing is written without one. */
	const given = (subject: string | undefined) => {
		if (subject === undefined) {
			throw new TypeError("claims-selection: a record without its subject");
		}
		return subject;
	};
	/** A write past its subject's erasure keeps nothing that would hold a claim back: it fails. */
	const unlessErased = (made: "created" | "exists" | "erased") => {
		if (made === "erased") throw new Unavailable("claims-selection: the subject is erased");
	};
	/** A record's own subject wins: a caller's that differs would file it where that erasure never looks. */
	const ownerOf = (own: string | undefined, theirs: string) => {
		if (own !== undefined && own !== theirs) {
			throw new Unavailable("claims-selection: a record kept for another subject");
		}
		return theirs;
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
	const pinOf = async (redemption: string) => {
		const found = await records.read(nameOf.pin(redemption));
		// A pin gone holds nothing back any more: the redemption fails rather than release unconstrained.
		if (found === undefined) throw new Unavailable("claims-selection");
		return read.pin(found);
	};
	/** The pin a redemption writes from, which code-grant gave its subject: one without is a defect. */
	const pinnedFor = async (redemption: string) => {
		const pin = await pinOf(redemption);
		if (pin.subject === undefined) {
			throw new Unavailable("claims-selection: a pin without its subject");
		}
		return { selection: pin.selection, subject: pin.subject };
	};
	const tokenWrite = async (access: Issued, target: Target, subject: string) =>
		holds(target)
			? write(
					nameOf.token(access.id),
					stored.target(target, subject),
					access.expiresAt - now() + tokenAllowanceMs,
					subject,
				)
			: "created";
	const keepForToken = async (access: Issued, target: Target, subject: string) =>
		unlessErased(await tokenWrite(access, target, subject));
	const tokenRecord = async (tokenId: string) => {
		const found = await records.read(nameOf.token(tokenId));
		return found === undefined ? undefined : read.target(found);
	};
	const selections: ClaimsSelections = {
		scopeOf: (claim) => scopes?.scopeOf(claim),
		select: async (client, subject, asked) => {
			bounded(asked);
			return {
				idToken: await cut(client, subject, asked.idToken),
				userinfo: await cut(client, subject, asked.userinfo),
			};
		},
		keepForCode: async (redemption, selection, lifetimeMs, subject) => {
			bounded(selection);
			if (!holds(selection.idToken) && !holds(selection.userinfo)) return;
			const owner = given(subject);
			const made = await write(
				nameOf.code(redemption),
				stored.code(selection, owner),
				lifetimeMs + codeMarginMs,
				owner,
			);
			// A code's name is made fresh for it: one already kept is not this code's.
			if (made !== "created") throw new Unavailable("claims-selection");
		},
		forCode: async (redemption) => (await pinOf(redemption)).selection,
		forToken: async (tokenId) => (await tokenRecord(tokenId))?.target,
		follow: async (redemption, familyId, lifetimeMs) => {
			const { selection, subject } = await pinnedFor(redemption);
			if (!selection || !holds(selection.userinfo)) return;
			const target = stored.target(selection.userinfo, subject);
			unlessErased(await write(nameOf.family(familyId), target, lifetimeMs, subject));
		},
		forRefreshed: async (familyId, client, subject, access) => {
			const found = await records.read(nameOf.family(familyId));
			if (found === undefined) return;
			const family = read.target(found);
			const owner = ownerOf(family.subject, subject);
			await keepForToken(access, await cut(client, subject, family.target), owner);
		},
	};
	const hook: RedemptionHook = {
		name: "claims-selection",
		pin: async (redemption, theirs) => {
			const found = await records.read(nameOf.code(redemption));
			const code = found === undefined ? undefined : read.code(found);
			const subject = ownerOf(code?.subject, given(theirs));
			const pin = stored.pin(code?.selection, subject);
			unlessErased(await write(nameOf.pin(redemption), pin, pinHoldMs, subject));
		},
		redeemed: async (redeemed) => {
			const { selection, subject } = await pinnedFor(redeemed.redemption);
			// The pin's subject is the code's: a redemption told of another is not this one's.
			ownerOf(subject, redeemed.subject);
			if (selection) await keepForToken(redeemed.access, selection.userinfo, subject);
		},
	};
	const tie: TokenTie = {
		name: "claims-selection",
		tieOf: async (tokenId) => {
			const found = await tokenRecord(tokenId);
			if (!found || found.target.constraints.length === 0) return { kind: "none" };
			// An exchanged token keeps the constraints only: its names were never asked of its client.
			const constraints = found.target.constraints;
			return {
				kind: "held",
				join: async (issued, subject) => {
					const owner = ownerOf(found.subject, given(subject));
					// Erased meanwhile: the tie ended, and the exchange takes back what it issued.
					return (await tokenWrite(issued, { names: [], constraints }, owner)) !== "erased";
				},
			};
		},
	};
	return { selections, hook, tie };
}
