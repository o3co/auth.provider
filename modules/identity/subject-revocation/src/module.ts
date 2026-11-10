import { defineModule, Unavailable } from "@mod/kernel";
import { comparedTo, subjectRevocationOf } from "./boundaries/boundaries.ts";
import { opened, writtenTo } from "./boundaries/written.ts";
import {
	type Revocations,
	revocationFollowers,
	revocations,
	subjectErasure,
	subjectRevocation,
} from "./contract.ts";
import { markedIn } from "./erasure/erasure.ts";
import { followedBy } from "./followers.ts";
import { boundaryStore } from "./store.ts";

export default defineModule(
	{ name: "subject-revocation", replicaSafe: true, takes: [boundaryStore, revocationFollowers] },
	(m) => [
		m.provide(revocations).by(async (c): Promise<Revocations> => {
			const boundaries = await c.get(boundaryStore);
			const write = writtenTo(boundaries);
			return {
				record: followedBy(write, await c.collect(revocationFollowers), c.log),
				compare: async (subject, time, kind, allowanceMs) => {
					const record = await boundaries.read(subject);
					if (record === undefined) return "valid";
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
	],
);
