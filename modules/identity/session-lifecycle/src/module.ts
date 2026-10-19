import { cookies } from "@mod/cookies";
import { defineModule } from "@mod/kernel";
import {
	type EntryLevel,
	entryRequirements,
	participants,
	sessionRules,
	sessions,
} from "@mod/session";
import { revocationFollowers, subjectRevocation } from "@mod/subject-revocation";
import { lifecycleOver } from "./lifecycle/lifecycle.ts";
import { raiseOver } from "./raise/raise.ts";
import { section } from "./section.ts";
import { closingList, cookieIndex, sessionStore, subjectSessions } from "./store.ts";

export default defineModule({ name: "session-lifecycle", section, replicaSafe: true }, (m) => [
	m.provide(sessions).by(async (c) => {
		const kept = await c.get(sessionStore);
		const lifetimeMs = c.section.lifetime * 1000;
		const sweepMs = c.section["sweep-interval"] * 1000;
		const lifecycle = lifecycleOver({
			kept,
			index: await c.get(cookieIndex),
			closings: await c.get(closingList),
			listed: await c.get(subjectSessions),
			revocation: await c.get(subjectRevocation),
			participants: await c.collect(participants),
			requirements: await c.collect(entryRequirements),
			jar: await c.get(cookies),
			clock: c.clock,
			random: c.random,
			log: c.log,
			lifetimeMs,
			sweepMs,
			credentialsMs: c.section["recent-authentication"] * 1000,
		});
		const recentMs = c.section["recent-authentication"] * 1000;
		c.every(sweepMs, lifecycle.sweep);
		const enteredAt = async (handle: string) => {
			const entry = await lifecycle.entryAt(handle, "use");
			return entry.kind === "entered" ? entry : undefined;
		};
		return {
			enter: async (request) => {
				const handle = await lifecycle.handleIn(request);
				return handle ? (await enteredAt(handle))?.session : undefined;
			},
			enterFor: async (request, level) => {
				const handle = await lifecycle.handleIn(request);
				return handle ? lifecycle.entryAt(handle, level) : { kind: "absent" };
			},
			entryOf: (handle: string, level: EntryLevel = "use") => lifecycle.entryAt(handle, level),
			stillOpen: async (handle) => (await enteredAt(handle)) !== undefined,
			openContext: async (handle) => (await enteredAt(handle))?.session.context,
			endsAt: async (handle) => (await enteredAt(handle))?.endsAt,
			complete: lifecycle.open,
			raise: raiseOver({ lifecycle, kept, clock: c.clock, lifetimeMs }),
			closeRequest: lifecycle.closeIn,
			close: lifecycle.close,
			recent: (at: number) => c.clock.now() - at <= recentMs,
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
]);
