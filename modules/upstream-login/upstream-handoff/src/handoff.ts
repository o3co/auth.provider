import {
	type BuildContext,
	type Clock,
	contract,
	extensionPoint,
	type Log,
	type Random,
	Unavailable,
} from "@mod/kernel";
import type { LoginOutcome } from "@mod/login-gates";
import { type Seal, seal } from "@mod/seal";
import type { Session } from "@mod/session";
import {
	type Receipt,
	type UpstreamLoginReceiver,
	type UpstreamTokens,
	upstreamLoginReceivers,
} from "@mod/upstreams";
import { heldOver } from "./held/held.ts";
import { type HeldLoginStore, heldLoginStore } from "./store.ts";

declare const joinedMark: unique symbol;
/** What a join gave each receiver, read by the handoff alone; its caller holds it for `withdrawn`. */
export type Joined = { readonly [joinedMark]: true };

/** A receiver given a join's tokens, and the receipt it answered. */
type Given = { readonly receiver: UpstreamLoginReceiver; readonly receipt: Receipt | undefined };

/** Hands a login's upstream tokens to the receivers once its session opens. */
export interface Handoff {
	/**
	 * For a login whose upstream gave tokens someone receives: the carry and the deadline for the
	 * caller to hand the login's gates, and what follows the login's outcome; a held login's tokens
	 * are kept for `lifetimeMs`, which is also how long until the deadline.
	 */
	of(
		idp: string,
		subject: string,
		tokens: UpstreamTokens | undefined,
		lifetimeMs: number,
	):
		| {
				readonly carry: string;
				readonly deadline: number;
				after(outcome: LoginOutcome): Promise<void>;
		  }
		| undefined;
	/** login-gates' news that a held login opened. */
	opened(session: Session, carry: string): Promise<void>;
	/** A link's tokens, handed now to the receivers of the open session it joined; one failing undoes the others and is unavailable. */
	joined(session: Session, idp: string, tokens: UpstreamTokens): Promise<Joined>;
	/** What a join gave taken back from each receiver it gave it to, and nothing written since, when its session closed, changed hands or could not tell after the join. */
	withdrawn(sessionId: string, idp: string, joined: Joined): Promise<void>;
}

export const handoff = contract<Handoff>("upstream-handoff.handoff");

/** The seal a held login's tokens are kept under: at most one. */
export const handoffSealing = extensionPoint<Seal>("upstream-handoff.sealing", {
	multiplicity: "many",
});

export const noHandoff: Handoff = {
	of: () => undefined,
	opened: async () => {},
	joined: async () => [] as unknown as Joined,
	withdrawn: async () => {},
};

interface Parts {
	readonly receivers: readonly UpstreamLoginReceiver[];
	readonly seal: Seal;
	readonly held: HeldLoginStore;
	readonly clock: Clock;
	readonly random: Random;
	readonly log: Log;
}

/** The handoff over the receivers in name order, or none where no module receives upstream tokens. */
export async function handoffIn(
	c: Pick<BuildContext<unknown>, "collect" | "get" | "refuse" | "clock" | "random" | "log">,
): Promise<Handoff> {
	const receivers = (await c.collect(upstreamLoginReceivers)).toSorted((a, b) =>
		a.name < b.name ? -1 : 1,
	);
	// Sealing is needed only where a module receives upstream tokens.
	if (receivers.length === 0) return noHandoff;
	const [contributed, ...others] = await c.collect(handoffSealing);
	if (others.length > 0)
		return c.refuse("upstream-handoff", "more than one sealing is contributed");
	return handoffWith({
		receivers,
		seal: contributed ?? (await c.get(seal)),
		held: await c.get(heldLoginStore),
		clock: c.clock,
		random: c.random,
		log: c.log,
	});
}

export function handoffWith(parts: Parts): Handoff {
	const tell = async (session: Session, idp: string, tokens: UpstreamTokens) => {
		for (const receiver of parts.receivers) {
			try {
				await receiver.received({ session, idp, tokens });
			} catch (error) {
				const kind = error instanceof Error ? error.name : typeof error;
				parts.log.error("upstream-handoff.receiver_failed", { receiver: receiver.name, kind });
			}
		}
	};
	/** Takes the tokens back from each receiver given them, with its receipt, going on past one that fails. */
	const withdraw = async (given: readonly Given[], sessionId: string, idp: string) => {
		for (const { receiver, receipt } of given) {
			try {
				await receiver.withdrawn(sessionId, idp, receipt);
			} catch {
				parts.log.warn("upstream-handoff.link_join_undo_failed", { receiver: receiver.name });
			}
		}
	};
	const held = heldOver(parts.seal, parts.held);
	return {
		of: (idp, subject, tokens, lifetimeMs) => {
			if (tokens === undefined) return undefined;
			// Past the deadline the kept tokens are gone, so the caller's gates refuse a resume.
			const deadline = parts.clock.now() + lifetimeMs;
			const carry = Buffer.from(parts.random.bytes(32)).toString("base64url");
			return {
				carry,
				deadline,
				after: async (outcome) => {
					if (outcome.kind === "opened") return tell(outcome.session, idp, tokens);
					// A refused login opens no session, now or later: nothing is kept to hand on.
					if (outcome.kind === "refused") return;
					await held.keep(carry, { idp, subject, heldAt: parts.clock.now(), tokens }, lifetimeMs);
				},
			};
		},
		opened: (session, carry) =>
			held.take(carry, session.context.subject, async (login) => {
				if (!login) return parts.log.warn("upstream-handoff.held_login_refused", {});
				// Said from the hold; handed over now, so the time since is spent.
				const spent = Math.ceil((parts.clock.now() - login.heldAt) / 1000);
				const { expiresInSeconds: expires, ...rest } = login.tokens;
				const tokens = (
					expires === undefined
						? rest
						: { ...rest, expiresInSeconds: Math.max(0, expires - Math.max(0, spent)) }
				) as UpstreamTokens;
				await tell(session, login.idp, tokens);
			}),
		joined: async (session, idp, tokens) => {
			const given: Given[] = [];
			for (const receiver of parts.receivers) {
				try {
					const receipt = (await receiver.received({ session, idp, tokens })) ?? undefined;
					given.push({ receiver, receipt });
				} catch (error) {
					const kind = error instanceof Error ? error.name : typeof error;
					parts.log.error("upstream-handoff.link_join_failed", { receiver: receiver.name, kind });
					await withdraw(given, session.id, idp);
					throw new Unavailable("upstream-handoff");
				}
			}
			return given as unknown as Joined;
		},
		withdrawn: (sessionId, idp, joined) =>
			withdraw(joined as unknown as readonly Given[], sessionId, idp),
	};
}
