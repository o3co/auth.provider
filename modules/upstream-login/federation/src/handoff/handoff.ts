import {
	type BuildContext,
	type Clock,
	contract,
	type Log,
	type Random,
	Unavailable,
} from "@mod/kernel";
import type { LoginFrom, LoginOutcome } from "@mod/login-gates";
import { type Seal, seal } from "@mod/seal";
import type { Session } from "@mod/session";
import {
	type Receipt,
	type UpstreamLoginReceiver,
	type UpstreamTokens,
	upstreamLoginReceivers,
} from "@mod/upstreams";
import { z } from "zod";
import type { Settings } from "../section.ts";
import { type StoredTransaction, type TransactionStore, transactionStore } from "../store.ts";

export const caller = "federation";

declare const joinedMark: unique symbol;
/** What a join gave each receiver, read by the handoff alone; its caller holds it for `withdrawn`. */
export type Joined = { readonly [joinedMark]: true };

/** A receiver given a join's tokens, and the receipt it answered. */
type Given = { readonly receiver: UpstreamLoginReceiver; readonly receipt: Receipt | undefined };

/** Hands a login's upstream tokens to the receivers once its session opens. */
export interface Handoff {
	/** For a login whose upstream gave tokens someone receives: what login-gates carries, and what follows it. */
	of(
		idp: string,
		subject: string,
		tokens: UpstreamTokens | undefined,
	): { readonly from: LoginFrom; after(outcome: LoginOutcome): Promise<void> } | undefined;
	/** login-gates' news that a held login opened. */
	opened(session: Session, carry: string): Promise<void>;
	/** A link's tokens, handed now to the receivers of the open session it joined; one failing undoes the others and is unavailable. */
	joined(session: Session, idp: string, tokens: UpstreamTokens): Promise<Joined>;
	/** What a join gave taken back from each receiver it gave it to, and nothing written since, when its session closed, changed hands or could not tell after the join. */
	withdrawn(sessionId: string, idp: string, joined: Joined): Promise<void>;
}

export const handoff = contract<Handoff>("federation.handoff");

export const noHandoff: Handoff = {
	of: () => undefined,
	opened: async () => {},
	joined: async () => [] as unknown as Joined,
	withdrawn: async () => {},
};

interface Parts {
	readonly receivers: readonly UpstreamLoginReceiver[];
	readonly seal: Seal;
	readonly transactions: TransactionStore;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
	readonly lifetimeMs: number;
}

const tokensShape = z.strictObject({
	accessToken: z.string(),
	tokenType: z.string(),
	refreshToken: z.string().optional(),
	idToken: z.string().optional(),
	expiresInSeconds: z.number().optional(),
	scope: z.array(z.string()),
});
const heldShape = z.strictObject({
	idp: z.string(),
	subject: z.string(),
	heldAt: z.number(),
	tokens: tokensShape,
});
const keptShape = z.strictObject({
	format: z.literal(1),
	sealed: z.string(),
	taken: z.literal(true).optional(),
});
type Kept = z.output<typeof keptShape>;
const keptOf = (stored: StoredTransaction | undefined) => {
	const read = keptShape.safeParse(stored);
	return read.success ? read.data : undefined;
};
const stored = (kept: Kept) => kept as unknown as StoredTransaction;
const contextOf = (carry: string) => `federation.held-login\n${carry}`;

export async function handoffIn(c: BuildContext<Settings>): Promise<Handoff> {
	const receivers = (await c.collect(upstreamLoginReceivers)).toSorted((a, b) =>
		a.name < b.name ? -1 : 1,
	);
	// Sealing is needed only where a module receives upstream tokens.
	if (receivers.length === 0) return noHandoff;
	return handoffWith({
		receivers,
		seal: await c.get(seal),
		transactions: await c.get(transactionStore),
		clock: c.clock,
		random: c.random,
		log: c.log,
		lifetimeMs: c.section["transaction-lifetime"] * 1000,
	});
}

/** login-gates' news that a held login opened, for the handoff. */
const openedWith = (handing: Pick<Handoff, "opened">) => ({
	caller,
	opened: handing.opened,
});

export const openedIn = async (c: BuildContext<Settings>) => openedWith(await c.get(handoff));

export function handoffWith(parts: Parts): Handoff {
	const tell = async (session: Session, idp: string, tokens: UpstreamTokens) => {
		for (const receiver of parts.receivers) {
			try {
				await receiver.received({ session, idp, tokens });
			} catch (error) {
				const kind = error instanceof Error ? error.name : typeof error;
				parts.log.error("federation.receiver_failed", { receiver: receiver.name, kind });
			}
		}
	};
	/** Takes the tokens back from each receiver given them, with its receipt, going on past one that fails. */
	const withdraw = async (given: readonly Given[], sessionId: string, idp: string) => {
		for (const { receiver, receipt } of given) {
			try {
				await receiver.withdrawn(sessionId, idp, receipt);
			} catch {
				parts.log.warn("federation.link_join_undo_failed", { receiver: receiver.name });
			}
		}
	};
	const opened = (kept: Kept, carry: string, subject: string) => {
		const plain = parts.seal.open(kept.sealed, contextOf(carry));
		const held = plain.kind === "opened" ? heldShape.safeParse(JSON.parse(plain.plain)) : undefined;
		return held?.success && held.data.subject === subject ? held.data : undefined;
	};
	return {
		of: (idp, subject, tokens) => {
			if (tokens === undefined) return undefined;
			// login-gates refuses a resume from the deadline on, when the kept tokens are gone.
			const deadline = parts.clock.now() + parts.lifetimeMs;
			const carry = Buffer.from(parts.random.bytes(32)).toString("base64url");
			return {
				from: { caller, carry, deadline },
				after: async (outcome) => {
					if (outcome.kind === "opened") return tell(outcome.session, idp, tokens);
					const held = { idp, subject, heldAt: parts.clock.now(), tokens };
					const sealed = parts.seal.seal(JSON.stringify(held), contextOf(carry));
					const saved = await parts.transactions.save(
						carry,
						stored({ format: 1, sealed }),
						parts.lifetimeMs,
					);
					if (saved !== "created") throw new Unavailable("federation");
				},
			};
		},
		opened: async (session, carry) => {
			const taking = await parts.transactions.update(carry, (record) => {
				const kept = keptOf(record);
				return kept && !kept.taken ? { value: stored({ ...kept, taken: true }) } : undefined;
			});
			const kept = keptOf(taking?.before);
			if (!kept || kept.taken || keptOf(taking?.after)?.taken !== true) return;
			try {
				const held = opened(kept, carry, session.context.subject);
				if (!held) return parts.log.warn("federation.held_login_refused", {});
				// Said from the hold; handed over now, so the time since is spent.
				const spent = Math.ceil((parts.clock.now() - held.heldAt) / 1000);
				const { expiresInSeconds: expires, ...rest } = held.tokens;
				const tokens = (
					expires === undefined
						? rest
						: { ...rest, expiresInSeconds: Math.max(0, expires - Math.max(0, spent)) }
				) as UpstreamTokens;
				await tell(session, held.idp, tokens);
			} finally {
				await parts.transactions.remove(carry);
			}
		},
		joined: async (session, idp, tokens) => {
			const given: Given[] = [];
			for (const receiver of parts.receivers) {
				try {
					const receipt = (await receiver.received({ session, idp, tokens })) ?? undefined;
					given.push({ receiver, receipt });
				} catch (error) {
					const kind = error instanceof Error ? error.name : typeof error;
					parts.log.error("federation.link_join_failed", { receiver: receiver.name, kind });
					await withdraw(given, session.id, idp);
					throw new Unavailable("federation");
				}
			}
			return given as unknown as Joined;
		},
		withdrawn: (sessionId, idp, joined) =>
			withdraw(joined as unknown as readonly Given[], sessionId, idp),
	};
}
