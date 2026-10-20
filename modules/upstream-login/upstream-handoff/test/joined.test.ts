import { isUnavailable } from "@mod/kernel";
import { recordingLog } from "@mod/kernel/testing";
import type { Seal } from "@mod/seal";
import type { Session } from "@mod/session";
import type { UpstreamLoginReceiver } from "@mod/upstreams";
import { expect, it } from "vitest";
import { handoffWith } from "../src/handoff.ts";
import type { HeldLoginStore } from "../src/store.ts";

const session: Session = {
	id: "s1",
	context: { subject: "alice", amr: ["pwd"], authenticatedAt: 0 },
};
const tokens = { accessToken: "up-1", tokenType: "Bearer", scope: [] };

/** A handoff over receivers that keep what reaches them; `failing` names the one that throws, `stuck` one that cannot undo. */
function joining(failing?: string, stuck?: string) {
	const calls: string[] = [];
	const receiver = (name: string): UpstreamLoginReceiver => ({
		name,
		received: async () => {
			if (name === failing) throw new TypeError("refused");
			calls.push(`received ${name}`);
			// One receiver keeps nothing it could name.
			return name === "three" ? undefined : `kept-by-${name}`;
		},
		// Thrown before any promise, as a receiver not written async would.
		withdrawn: (id, idp, receipt) => {
			if (name === stuck) throw new TypeError("stuck");
			calls.push(`withdrawn ${name} ${id} ${idp} ${receipt}`);
			return Promise.resolve();
		},
	});
	const logged = recordingLog();
	const handoff = handoffWith({
		receivers: [receiver("one"), receiver("two"), receiver("three")],
		seal: {} as Seal,
		held: {} as HeldLoginStore,
		clock: { now: () => 0 },
		random: { bytes: (n) => new Uint8Array(n) },
		log: logged.log,
	});
	return { calls, logged, handoff };
}

it("hands a link's tokens to every receiver of the session it joined", async () => {
	const j = joining();
	await j.handoff.joined(session, "corp", tokens);
	expect(j.calls).toEqual(["received one", "received two", "received three"]);
});

it("undoes what it gave when a receiver fails, and fails as unavailable, logging which", async () => {
	const j = joining("two");
	await expect(j.handoff.joined(session, "corp", tokens)).rejects.toSatisfy(isUnavailable);
	expect(j.calls).toEqual(["received one", "withdrawn one s1 corp kept-by-one"]);
	expect(j.logged.lines().map((l) => [l.level, l.event, l.fields])).toEqual([
		["error", "upstream-handoff.link_join_failed", { receiver: "two", kind: "TypeError" }],
	]);
});

it("still undoes the rest and fails as unavailable when one cannot undo, warning which", async () => {
	const j = joining("three", "one");
	await expect(j.handoff.joined(session, "corp", tokens)).rejects.toSatisfy(isUnavailable);
	expect(j.calls).toEqual(["received one", "received two", "withdrawn two s1 corp kept-by-two"]);
	expect(j.logged.lines().map((l) => [l.level, l.event, l.fields])).toEqual([
		["error", "upstream-handoff.link_join_failed", { receiver: "three", kind: "TypeError" }],
		["warn", "upstream-handoff.link_join_undo_failed", { receiver: "one" }],
	]);
});

it("takes a link's tokens back from each receiver it gave them to, with its receipt, going on past one that cannot, warning which", async () => {
	const j = joining(undefined, "two");
	const joined = await j.handoff.joined(session, "corp", tokens);
	j.calls.length = 0;
	await j.handoff.withdrawn("s1", "corp", joined);
	expect(j.calls).toEqual([
		"withdrawn one s1 corp kept-by-one",
		"withdrawn three s1 corp undefined",
	]);
	expect(j.logged.lines().map((l) => [l.level, l.event, l.fields])).toEqual([
		["warn", "upstream-handoff.link_join_undo_failed", { receiver: "two" }],
	]);
});
