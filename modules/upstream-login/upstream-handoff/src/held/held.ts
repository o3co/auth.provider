import { Unavailable } from "@mod/kernel";
import type { Seal } from "@mod/seal";
import type { UpstreamTokens } from "@mod/upstreams";
import { z } from "zod";
import type { HeldLoginStore, StoredHeldLogin } from "../store.ts";

/** A login a gate held: the upstream it came from, its local subject, when it was held, its tokens. */
export interface HeldLogin {
	readonly idp: string;
	readonly subject: string;
	readonly heldAt: number;
	readonly tokens: UpstreamTokens;
}

/** Held logins kept sealed by their carry, each taken once. */
export interface Held {
	/** Keeps the login sealed under the carry for `lifetimeMs`; unavailable when it cannot be kept. */
	keep(carry: string, login: HeldLogin, lifetimeMs: number): Promise<void>;
	/**
	 * Takes the login kept under the carry once, hands it to `use` (none when it does not open as
	 * one of `subject`), then removes it. Nothing is handed where none is kept or it was taken.
	 */
	take(
		carry: string,
		subject: string,
		use: (login: HeldLogin | undefined) => Promise<void>,
	): Promise<void>;
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
const keptOf = (stored: StoredHeldLogin | undefined) => {
	const read = keptShape.safeParse(stored);
	return read.success ? read.data : undefined;
};
const stored = (kept: Kept) => kept as unknown as StoredHeldLogin;
const contextOf = (carry: string) => `upstream-handoff.held-login\n${carry}`;

export function heldOver(seal: Seal, store: HeldLoginStore): Held {
	const opened = (kept: Kept, carry: string, subject: string) => {
		const plain = seal.open(kept.sealed, contextOf(carry));
		const held = plain.kind === "opened" ? heldShape.safeParse(JSON.parse(plain.plain)) : undefined;
		return held?.success && held.data.subject === subject ? (held.data as HeldLogin) : undefined;
	};
	return {
		keep: async (carry, login, lifetimeMs) => {
			const sealed = seal.seal(JSON.stringify(login), contextOf(carry));
			const saved = await store.save(carry, stored({ format: 1, sealed }), lifetimeMs);
			if (saved !== "created") throw new Unavailable("upstream-handoff");
		},
		take: async (carry, subject, use) => {
			const taking = await store.update(carry, (record) => {
				const kept = keptOf(record);
				return kept && !kept.taken ? { value: stored({ ...kept, taken: true }) } : undefined;
			});
			const kept = keptOf(taking?.before);
			if (!kept || kept.taken || keptOf(taking?.after)?.taken !== true) return;
			try {
				await use(opened(kept, carry, subject));
			} finally {
				await store.remove(carry);
			}
		},
	};
}
