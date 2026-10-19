import { sessionIssuances } from "@mod/grants";
import {
	type BuildContext,
	contract,
	defineModule,
	type Log,
	setting,
	Unavailable,
} from "@mod/kernel";
import { participants } from "@mod/session-participants";
import { referenceOf, type Tokens, tokens } from "@mod/tokens";
import { z } from "zod";
import { sessionTokens } from "./contract.ts";
import {
	type IssuedTokens,
	issuedTokens,
	type PendingSessions,
	pendingSessions,
	type TokenIndex,
	tokenIndex,
} from "./store.ts";

const section = z.strictObject({
	"sweep-interval": setting
		.duration("s")
		.pipe(z.number().int().min(1).max(3600))
		.prefault("30s")
		.describe(
			"How often each host revokes the tokens of pushed-out references left unrevoked, from `1s` to `1h` in whole seconds.",
		),
	"push-out-margin": z
		.number()
		.int()
		.min(0)
		.max(10_000)
		.prefault(8)
		.describe(
			"How far below a session's cap an add lists the session before it may push a reference out: the adds expected to come at once. A larger margin narrows the crash window, at one more write near the cap; it must stay below the cap.",
		),
});

/** Each id is kept this long past its token, so clock differences never drop it early. */
const allowanceMs = 120_000;

interface Parts {
	readonly kept: IssuedTokens;
	readonly index: TokenIndex;
	readonly sessions: PendingSessions;
	readonly margin: number;
	readonly revoking: Pick<Tokens, "revokeReferenced">;
	readonly now: () => number;
	readonly log: Log;
}

/** Revokes what the session's set has awaiting, settling each, then takes the session off the list once none awaits. */
const settler =
	({ kept, revoking, sessions }: Parts) =>
	async (session: string) => {
		for (const reference of await kept.awaiting(session)) {
			const done = await revoking.revokeReferenced(reference);
			if (done.kind === "unsupported") throw new Unavailable("session-tokens");
			await kept.settled(session, reference);
		}
		// Another add may have pushed one out meanwhile: the session stays listed for it.
		if ((await kept.awaiting(session)).length === 0) await sessions.done(session);
	};

/** Records a token as issued from a session. */
const recorder =
	(parts: Parts) =>
	async (session: string, token: { readonly id: string; readonly expiresAt: number }) => {
		const { kept, index, sessions, margin } = parts;
		const keepMs = token.expiresAt - parts.now() + allowanceMs;
		// Indexed before kept, so every kept reference names its session in the index.
		const saved = await index.save(token.id, session, keepMs);
		if (saved === "exists" && (await index.read(token.id)) !== session) {
			throw new Unavailable("session-tokens");
		}
		// Listed before an add that may push one out, so a host stopped past the add leaves it to the sweep.
		const near = (await kept.members(session)).length >= kept.size - margin;
		if (near) await sessions.add(session);
		const { pushedOut } = await kept.add(session, referenceOf(token), keepMs);
		if (pushedOut.length === 0) return;
		parts.log.info("session-tokens.pushed_out", { count: pushedOut.length });
		// Adds at once past the margin pushed one out unlisted: listed now, the window left.
		if (!near) await sessions.add(session);
		await settler(parts)(session);
	};

const partsOf = async (c: BuildContext<z.output<typeof section>>): Promise<Parts> => {
	const kept = await c.get(issuedTokens);
	if (c.section["push-out-margin"] >= kept.size) {
		c.refuse(
			"session-tokens.push-out-margin",
			"it must stay below the number of references the store keeps to a session",
		);
	}
	return {
		kept,
		index: await c.get(tokenIndex),
		sessions: await c.get(pendingSessions),
		margin: c.section["push-out-margin"],
		revoking: await c.get(tokens),
		now: c.clock.now,
		log: c.log,
	};
};

/** The parts built once, so the margin is checked once. */
const built = contract<Parts>("session-tokens.parts");

export default defineModule({ name: "session-tokens", section }, (m) => [
	m.provide(built).by(partsOf),
	m.provide(sessionTokens).by(async (c) => {
		const parts = await c.get(built);
		const settle = settler(parts);
		c.every(c.section["sweep-interval"] * 1000, async () => {
			const { failed } = await parts.sessions.each(settle);
			if (failed > 0) c.log.warn("session-tokens.revoke_retry_failed", { count: failed });
		});
		return {
			sessionOf: async (tokenId) => {
				const handle = await parts.index.read(tokenId);
				return handle === undefined ? { kind: "unbound" } : { kind: "bound", handle };
			},
		};
	}),
	m.contribute(sessionIssuances).by(async (c) => ({ issued: recorder(await c.get(built)) })),
	m.contribute(participants).by(async (c) => {
		const kept = await c.get(issuedTokens);
		const revoking = await c.get(tokens);
		if (!revoking.revocable()) {
			return c.refuse(
				"session-tokens",
				"where access tokens cannot be revoked, tokens outlive a closed session",
			);
		}
		return {
			name: "session-tokens",
			// Safe to repeat and to run on several hosts at once: revoking a reference twice is harmless.
			closing: async (session) => {
				for (const { member: reference } of await kept.members(session.id)) {
					const done = await revoking.revokeReferenced(reference);
					if (done.kind === "unsupported") throw new Unavailable("session-tokens");
				}
				// What the set pushed out is the session's too, if not yet revoked.
				for (const reference of await kept.awaiting(session.id)) {
					const done = await revoking.revokeReferenced(reference);
					if (done.kind === "unsupported") throw new Unavailable("session-tokens");
					await kept.settled(session.id, reference);
				}
			},
		};
	}),
]);
