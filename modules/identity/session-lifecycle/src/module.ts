import { cookies } from "@mod/cookies";
import { defineModule } from "@mod/kernel";
import {
	closingParticipants,
	type EntryLevel,
	entryJudge,
	sessionRules,
	sessions,
} from "@mod/session";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { lifecycleOver } from "./lifecycle/lifecycle.ts";
import { raiseOver } from "./raise/raise.ts";
import { section } from "./section.ts";
import { closingList, cookieIndex, sessionStore, subjectSessions } from "./store.ts";

export default defineModule(
	{
		name: "session-lifecycle",
		section,
		replicaSafe: true,
		takes: [
			cookies,
			closingList,
			cookieIndex,
			sessionStore,
			subjectSessions,
			closingParticipants,
			entryJudge,
			subjectRevocation,
		],
	},
	(m) => [
		m.provide(sessions).by(async (c) => {
			const kept = await c.get(sessionStore);
			// Kept elsewhere, as session's seams: none composed is refused, never taken as no rule.
			const [judge] = await c.collect(entryJudge);
			const [closing] = await c.collect(closingParticipants);
			if (!judge || !closing) {
				const missing = [
					...(judge ? [] : [entryJudge.label]),
					...(closing ? [] : [closingParticipants.label]),
				];
				const reason = "needs exactly one contribution (0)";
				return c.refuseAll(missing.map((where) => ({ where, reason })));
			}
			// The one recent-authentication window, for entry's floor and for `recent` alike.
			const recentMs = c.section["recent-authentication"] * 1000;
			const recent = (at: number) => c.clock.now() - at <= recentMs;
			const lifetimeMs = c.section.lifetime * 1000;
			const sweepMs = c.section["sweep-interval"] * 1000;
			const lifecycle = lifecycleOver({
				kept,
				index: await c.get(cookieIndex),
				closings: await c.get(closingList),
				listed: await c.get(subjectSessions),
				revocation: await c.get(subjectRevocation),
				judge,
				closing,
				jar: await c.get(cookies),
				clock: c.clock,
				random: c.random,
				log: c.log,
				lifetimeMs,
				sweepMs,
				recent,
			});
			c.every(sweepMs, lifecycle.sweep);
			return {
				enter: async (request) => {
					const entry = await lifecycle.entryIn(request, "use");
					return entry.kind === "entered" ? entry.session : undefined;
				},
				enterFor: lifecycle.entryIn,
				entryOf: (handle: string, level: EntryLevel = "use") => lifecycle.entryAt(handle, level),
				complete: lifecycle.open,
				raise: raiseOver({ lifecycle, kept, clock: c.clock, lifetimeMs }),
				closeRequest: lifecycle.closeIn,
				close: lifecycle.close,
				recent,
			};
		}),
		m.contribute(revocationFollowers).by(async (c) => {
			const listed = await c.get(subjectSessions);
			const lateSessions = c.late(sessions);
			return {
				name: "session-lifecycle",
				follow: (subject) =>
					sessionRules.closeListed(subject, listed, (handle) => lateSessions().close(handle)),
			};
		}),
	],
);
