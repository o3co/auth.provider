import { contract, defineModule, probes, Unavailable } from "@mod/kernel";
import { comparedTo, subjectRevocationOf } from "./boundaries/boundaries.ts";
import { markIn, opened, writtenTo } from "./boundaries/written.ts";
import {
	erasureFence,
	erasureGuards,
	type Revocations,
	revocationFollowers,
	revocations,
	subjectErasure,
	subjectRevocation,
} from "./contract.ts";
import { markedIn } from "./erasure/erasure.ts";
import { type Enablement, erasureMark, fenceOver } from "./erasure/gate.ts";
import { followedBy } from "./followers.ts";
import { boundaryStore } from "./store.ts";

/** The boot gate's reading: whether the composition guards erasure, and the mark as read. */
const erasureGate = contract<{
	readonly guarded: boolean;
	readonly enabled: () => Promise<Enablement>;
}>("subject-revocation.erasure-gate");

export default defineModule(
	{
		name: "subject-revocation",
		replicaSafe: true,
		takes: [boundaryStore, revocationFollowers, erasureGuards],
	},
	(m) => [
		// Guarded is known without the store: a guarded composition starts whatever the store answers.
		m.provide(erasureGate).by(async (c) => {
			const boundaries = await c.get(boundaryStore);
			const guarded = boundaries.fence !== undefined && (await c.collect(erasureGuards)).length > 0;
			const mark = erasureMark(boundaries);
			if (mark.cannotTell) {
				const why = !boundaries.fence
					? "nor fences, so erasure reads as off"
					: guarded
						? "so every bundle is fenced"
						: "and no module guards it, so no issuance is fenced and erasure reads as off";
				c.log.warn("subject-revocation.erasure_unknown", {
					reason: `the boundary store does not tell whether erasure is enabled, ${why}; 0.22 refuses it`,
				});
			}
			if (!guarded && (await mark.read()) === "on") {
				return c.refuse(
					"subject-revocation",
					"erasure is enabled, yet no module guards it or the boundary store does not fence",
				);
			}
			return { guarded, enabled: mark.read };
		}),
		m.provide(revocations).by(async (c): Promise<Revocations> => {
			const boundaries = await c.get(boundaryStore);
			const write = writtenTo(boundaries);
			return {
				record: followedBy(write, await c.collect(revocationFollowers), c.log),
				compare: async (subject, time, kind, allowanceMs) => {
					const record = await boundaries.read(subject);
					if (record === undefined) return "valid";
					// A mark of a time revokes all, whatever else the record holds, as marking answers it.
					if (typeof markIn(record) === "number") return "revoked";
					const held = opened(record);
					if (held === undefined) throw new Unavailable("subject-revocation");
					return comparedTo(held, time, kind, allowanceMs);
				},
			};
		}),
		m.provide(subjectRevocation).by(async (c) => subjectRevocationOf(await c.get(revocations))),
		m
			.provide(subjectErasure)
			.by(async (c) => ({ markErased: markedIn(await c.get(boundaryStore)) })),
		m
			.provide(erasureFence)
			.by(async (c) => fenceOver(await c.get(boundaryStore), (await c.get(erasureGate)).enabled)),
		// An unguarded composition whose mark is unread stays out of traffic until the mark reads off.
		m.contribute(probes).by(async (c) => {
			const { guarded, enabled } = await c.get(erasureGate);
			return {
				name: "subject-revocation.erasure",
				check: async () => {
					if (guarded) return;
					const state = await enabled();
					if (state === "unread") throw new Error("whether erasure is enabled cannot be read yet");
					if (state === "on")
						throw new Error("erasure is enabled, yet this composition does not guard it");
				},
			};
		}),
	],
);
