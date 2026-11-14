import type { Walk } from "@mod/erasure-extensions";
import { expect, it } from "vitest";
import type { RoundTripsWalked, StoredRoundTrip } from "../../store.ts";
import { roundTripEraser } from "../eraser.ts";

const walk: Walk = { sweep: async () => ({ keys: [], server: "one" }) };
const trip = { format: 1, carried: { by: "link", kept: { session: "s", subject: "alice" } } };

/** A store walking `held`, noting what each visit answered, or answering `answer`. */
const walking = (held: unknown[], visits: boolean[] = [], answer?: RoundTripsWalked) => ({
	walk: async (
		_w: Walk,
		visit: (r: StoredRoundTrip) => Promise<boolean> | boolean,
		_signal: AbortSignal,
	) => {
		if (answer) return answer;
		for (const one of held) {
			const going = await visit(one as StoredRoundTrip);
			visits.push(going);
			if (!going) return { kind: "stopped" } as const;
		}
		return { kind: "walked" } as const;
	},
});

it("erases nothing, and migrates once no round trip remains", async () => {
	const signal = new AbortController().signal;
	const eraser = roundTripEraser(walking([]));
	expect([eraser.name, eraser.erasable]).toEqual(["upstream-round-trip", true]);
	expect(await eraser.online("alice", signal)).toEqual({ reports: [], logoutGaps: 0 });
	expect(await eraser.window(["alice"], walk, signal)).toEqual({ reports: [], logoutGaps: 0 });
	expect(await eraser.migrate(walk, signal)).toEqual([]);
});

it("stops its migration on the first round trip it meets, never opening one, the reason giving the bound", async () => {
	const visits: boolean[] = [];
	const [answer] = await roundTripEraser(walking([trip, trip], visits)).migrate(
		walk,
		new AbortController().signal,
	);
	expect(visits).toEqual([false]);
	expect(answer?.kind).toBe("owner-stopped");
	const { reason } = answer as { reason: string };
	expect(reason).toContain(
		"run again up to 3,600 s after the provider's connections were locked out",
	);
	expect(reason).toContain("a stop past that means something still begins round trips");
	expect(reason).not.toContain("alice");
});

it("stops on a walk that did not finish, and throws the signal's reason where the run was cut short", async () => {
	for (const why of ["walk-unsteady", "unavailable"] as const) {
		const store = walking([], [], { kind: "unfinished", reason: why });
		expect(await roundTripEraser(store).migrate(walk, new AbortController().signal)).toEqual([
			{ kind: "owner-stopped", reason: `the round trips' walk did not finish (${why}); run again` },
		]);
	}
	const cut = new AbortController();
	const store = walking([], [], { kind: "unfinished", reason: "aborted" });
	const aborting = roundTripEraser({
		walk: async (...args) => {
			cut.abort(new Error("stopped by the operator"));
			return store.walk(...args);
		},
	});
	await expect(aborting.migrate(walk, cut.signal)).rejects.toThrow("stopped by the operator");
	await expect(aborting.online("alice", cut.signal)).rejects.toThrow("stopped by the operator");
});

it("is not erasable where the store offers no walk", async () => {
	const eraser = roundTripEraser({});
	expect(eraser.erasable).toBe(false);
	expect(await eraser.migrate(walk, new AbortController().signal)).toEqual([]);
});
