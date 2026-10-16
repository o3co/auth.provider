import type { Clock } from "@mod/kernel";
import type { Sessions } from "@mod/session";
import { fromStored, type Lifecycle, toStored } from "../lifecycle/lifecycle.ts";
import type { SessionStore } from "../store.ts";

export interface RaiseParts {
	readonly lifecycle: Lifecycle;
	readonly kept: SessionStore;
	readonly clock: Clock;
	readonly lifetimeMs: number;
}

/** A session's amr once a raise adds `amr`, and what the raise added, each value once. */
export function raisedBy(held: readonly string[], amr: readonly string[]) {
	const raisedAmr = [...new Set(amr)];
	return { amr: [...new Set([...held, ...raisedAmr])], raisedAmr };
}

/** Raises the request's live session under a new cookie, keeping its handle and authentication time. */
export function raiseOver({ lifecycle, kept, clock, lifetimeMs }: RaiseParts): Sessions["raise"] {
	return async (request, amr) => {
		const secret = lifecycle.secretIn(request);
		if (!secret) return undefined;
		const handle = await lifecycle.handleIn(request);
		const live = handle && (await lifecycle.liveAt(handle));
		if (!live || !handle) return undefined;
		// What is left of the session's lifetime, on the clock its opening was taken on.
		const leftMs = Math.max(1, live.openedAt + lifetimeMs - clock.now());
		const { cookie } = await lifecycle.issueSecret(handle, leftMs);
		// The old cookie is retired first, so it never enters a raised session.
		await lifecycle.retireSecret(secret);
		const at = clock.now();
		const written = await kept
			.update(handle, (stored) => {
				const was = fromStored(stored);
				if (was?.state !== "open") return undefined;
				return { value: toStored({ ...was, ...raisedBy(was.amr, amr), raisedAt: at }) };
			})
			.catch(() => "failed" as const);
		// The new cookie still points at the session; only the raise is to try again.
		if (written === "failed") {
			return { session: lifecycle.sessionOf(handle, live), cookies: [cookie], raised: false };
		}
		const after = written && fromStored(written.after);
		if (after?.state !== "open") return undefined;
		return { session: lifecycle.sessionOf(handle, after), cookies: [cookie], raised: true };
	};
}
