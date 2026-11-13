import { erasers } from "@mod/erasure-extensions";
import { contract, defineModule, probes, Unavailable } from "@mod/kernel";
import { comparedTo, subjectRevocationOf } from "./boundaries/boundaries.ts";
import { erasedIn, markIn, opened, writtenTo } from "./boundaries/written.ts";
import {
	erasedSubjects,
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

/** Whether erasure is enabled, as this process reads it, once: the fence and the gate share it. */
const erasureReading = contract<ReturnType<typeof erasureMark>>(
	"subject-revocation.erasure-reading",
);

/** The boot gate's reading: whether the composition covers erasure, and the mark as read. */
const erasureGate = contract<{
	readonly covered: boolean;
	readonly enabled: () => Promise<Enablement>;
}>("subject-revocation.erasure-gate");

export default defineModule(
	{
		name: "subject-revocation",
		replicaSafe: true,
		takes: [boundaryStore, revocationFollowers, erasureGuards, erasers],
	},
	(m) => [
		m.provide(erasureReading).by(async (c) => erasureMark(await c.get(boundaryStore))),
		// Covered is known without the store: a covered composition starts whatever the store answers.
		// The gate collects erasers, so no eraser's build may reach it: only the probe takes it.
		m.provide(erasureGate).by(async (c) => {
			const boundaries = await c.get(boundaryStore);
			const guarded = boundaries.fence !== undefined && (await c.collect(erasureGuards)).length > 0;
			const unerasable = (await c.collect(erasers)).filter((e) => !e.erasable).map((e) => e.name);
			const covered = guarded && unerasable.length === 0;
			const mark = await c.get(erasureReading);
			// What a node that cannot tell must keep to, in the runbook's own words.
			const rule = "this node must never serve a deployment where erasure is enabled";
			if (mark.cannotTell) {
				const why = !boundaries.fence
					? "nor fences, so erasure reads as off"
					: !guarded
						? "and no module guards it, so no issuance is fenced and erasure reads as off"
						: covered
							? "so every bundle is fenced"
							: "so every bundle is fenced, yet not every owner erases, and erasure reads as off";
				c.log.warn("subject-revocation.erasure_unknown", {
					reason: `the boundary store does not tell whether erasure is enabled, ${why}: ${rule}; 0.22 refuses it`,
				});
			}
			if (unerasable.length > 0) {
				c.log.warn("subject-revocation.erasure_unerasable", {
					owners: unerasable.join(" "),
					reason: `their stores cannot erase, so erasure cannot be enabled here${mark.cannotTell ? `: ${rule}` : ""}; 0.22 requires them`,
				});
			}
			if (!covered && (await mark.read()) === "on") {
				// Every reason at once, so the operator is not refused again for the one left unnamed.
				const reasons = [
					...(guarded ? [] : ["no module guards it or the boundary store does not fence"]),
					...(unerasable.length > 0 ? [`these cannot erase: ${unerasable.join(", ")}`] : []),
				];
				return c.refuse("subject-revocation", `erasure is enabled, yet ${reasons.join("; and ")}`);
			}
			return { covered, enabled: mark.read };
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
		// Where this process read erasure off at its start, no subject is marked (TLC's A2): no read.
		m.provide(erasedSubjects).by(async (c) => {
			const marked = erasedIn(await c.get(boundaryStore));
			const { read } = await c.get(erasureReading);
			return { erased: async (subject) => ((await read()) === "off" ? false : marked(subject)) };
		}),
		m
			.provide(erasureFence)
			.by(async (c) => fenceOver(await c.get(boundaryStore), (await c.get(erasureReading)).read)),
		// An uncovered composition whose mark is unread stays out of traffic until the mark reads off.
		m.contribute(probes).by(async (c) => {
			const { covered, enabled } = await c.get(erasureGate);
			return {
				name: "subject-revocation.erasure",
				check: async () => {
					if (covered) return;
					const state = await enabled();
					if (state === "unread") throw new Error("whether erasure is enabled cannot be read yet");
					if (state === "on")
						throw new Error("erasure is enabled, yet this composition does not cover it");
				},
			};
		}),
	],
);
