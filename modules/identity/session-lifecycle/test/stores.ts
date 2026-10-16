import { defineModule, Unavailable } from "@mod/kernel";
import { unavailableSwitch } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import {
	type ClosingList,
	type CookieIndex,
	closingList,
	cookieIndex,
	type SessionStore,
	type StoredSession,
	type SubjectSessions,
	sessionStore,
	subjectSessions,
} from "../src/store.ts";

/**
 * session-lifecycle's store interfaces on the records stand-in, with lifetimes on the composition's clock;
 * each goes through a switch that can make its calls unavailable.
 */
export function memoryStores() {
	let clock = () => 0;
	const size = { shards: 4, perShard: 50 };
	const kept = memoryRecords<StoredSession>(() => clock(), size);
	const index = memoryRecords<string>(() => clock(), size);
	const down = {
		sessions: unavailableSwitch<SessionStore>("session store"),
		cookies: unavailableSwitch<CookieIndex>("cookie index"),
		closing: unavailableSwitch<ClosingList>("closing list"),
		listed: unavailableSwitch<SubjectSessions>("subject sessions"),
	};
	/** The writes that take effect once more and then answer Unavailable, as a place whose answer was lost. */
	const lost = new Set<"sessions.save" | "listed.add" | "cookies.save">();
	const answered = async <T>(
		write: "sessions.save" | "listed.add" | "cookies.save",
		done: Promise<T>,
	) => {
		const value = await done;
		if (lost.delete(write)) throw new Unavailable(write);
		return value;
	};
	const sets = kept.keyedSets(size.perShard);
	const listed = down.listed.wrap({
		...sets,
		add: (...given) => answered("listed.add", sets.add(...given)),
	});
	const module = defineModule({ name: "session-stores" }, (m) => [
		m.provide(sessionStore).by((c) => {
			clock = c.clock.now;
			const { create: save, read, change: update } = kept.records;
			return down.sessions.wrap({
				save: (...given) => answered("sessions.save", save(...given)),
				read,
				update,
			});
		}),
		m.provide(cookieIndex).by(() => {
			const { create: save, read, remove } = index.records;
			return down.cookies.wrap({
				save: (...given) => answered("cookies.save", save(...given)),
				read,
				remove,
			});
		}),
		m.provide(closingList).by(() => down.closing.wrap(kept.deferred)),
		m.provide(subjectSessions).by(() => listed),
	]);
	return { module, kept, index, listed, listingCap: size.perShard, down, lost };
}
