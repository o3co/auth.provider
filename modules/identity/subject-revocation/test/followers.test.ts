import { assemble, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import { revocationFollowers, revocations, subjectRevocation } from "../src/contract.ts";
import revocationModule from "../src/module.ts";
import { boundaryStore } from "../src/store.ts";
import { subjectRevocationStandIn } from "../src/testing.ts";
import { memoryBoundaries } from "./stores.ts";

const now = 1_800_000_000_000;
/** Not in name order, so the calls show collect order. */
const collectOrder = ["b", "a", "c"];

/** Followers that note each call, and what the boundary already said when it came. */
function following(failing: readonly string[] = []) {
	const calls: { name: string; subject: string; keepDelegations: boolean; seen: string }[] = [];
	const module = defineModule({ name: "followers" }, (m) =>
		collectOrder.map((name) =>
			m.contribute(revocationFollowers).by((c) => {
				const boundaries = c.late(revocations);
				return {
					name,
					follow: async (subject, { keepDelegations }) => {
						const seen = await boundaries().compare(subject, now - 1000, "sessions");
						calls.push({ name, subject, keepDelegations, seen });
						if (failing.includes(name)) throw new TypeError("not now");
					},
				};
			}),
		),
	);
	return { calls, module };
}

const compositions = {
	"subject-revocation": () => {
		const stores = memoryBoundaries();
		const store = defineModule({ name: "boundaries" }, (m) => [
			m.provide(boundaryStore).by(() => stores.boundaries),
		]);
		return { modules: [revocationModule, store], down: stores.down };
	},
	"the stand-in": () => ({ modules: [subjectRevocationStandIn], down: undefined }),
};

for (const [name, composed] of Object.entries(compositions)) {
	describe(`followers of a revocation: ${name}`, () => {
		async function boot(failing: readonly string[] = []) {
			const { modules, down } = composed();
			const followers = following(failing);
			const recorded = recordingLog();
			const app = await assemble({
				modules: [...modules, followers.module],
				config: kernelConfig(),
				runtime: quietRuntime({ clock: { now: () => now }, log: recorded.log }),
			});
			return { app, down, recorded, calls: followers.calls };
		}

		it("calls each follower once the boundary is written, one at a time in collect order, saying whether delegations were kept", async () => {
			const { app, calls } = await boot();
			expect(await app.get(revocations).record("alice", { keepDelegations: true })).toEqual({
				complete: true,
			});
			await app.get(subjectRevocation).revoke("bob");
			expect(calls).toEqual([
				...collectOrder.map((n) => ({
					name: n,
					subject: "alice",
					keepDelegations: true,
					seen: "revoked",
				})),
				...collectOrder.map((n) => ({
					name: n,
					subject: "bob",
					keepDelegations: false,
					seen: "revoked",
				})),
			]);
		});

		it("answers incomplete, keeps the boundary and calls the rest when a follower fails, logging it by name and kind", async () => {
			const { app, calls, recorded } = await boot(["b"]);
			expect(await app.get(revocations).record("alice")).toEqual({ complete: false });
			expect(calls.map((call) => call.name)).toEqual(collectOrder);
			expect(await app.get(revocations).compare("alice", now - 1000, "sessions")).toBe("revoked");
			expect(recorded.lines().filter((line) => line.level === "warn")).toEqual([
				{
					level: "warn",
					event: "subject-revocation.follower_failed",
					fields: { follower: "b", kind: "TypeError" },
				},
			]);
		});

		it.skipIf(name === "the stand-in")(
			"calls no follower when the boundary could not be written",
			async () => {
				const { app, calls, down } = await boot();
				down?.failNext("update");
				await expect(app.get(revocations).record("alice")).rejects.toSatisfy(isUnavailable);
				expect(calls).toEqual([]);
			},
		);
	});
}
