import { createHash } from "node:crypto";
import { type BuildContext, type Clock, type Random, Unavailable } from "@mod/kernel";
import type { Reauths } from "./contract.ts";
import { fromStored, toStored } from "./record.ts";
import { type ReauthStore, reauthStore } from "./store.ts";

const lifetimeMs = 600_000;

const digest = (params: ReadonlyMap<string, string>) =>
	createHash("sha256").update(canonical(params)).digest("base64url");
const canonical = (params: ReadonlyMap<string, string>) =>
	JSON.stringify(
		[...params]
			.filter(([name]) => name !== "reauth")
			// prompt holds a set of words: one spelling for every order and repetition.
			.map(([name, value]): [string, string] => [
				name,
				name === "prompt" ? [...new Set(value.split(" ").filter(Boolean))].sort().join(" ") : value,
			])
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
	);

export interface ReauthsParts {
	readonly store: ReauthStore;
	readonly clock: Clock;
	readonly random: Random;
}

export function reauthsWith({ store, clock, random }: ReauthsParts): Reauths {
	const newName = () => Buffer.from(random.bytes(32)).toString("base64url");
	return {
		async remember(params, at, stepUp) {
			const reauth = newName();
			const record = toStored({
				format: 1,
				at,
				request: digest(params),
				...(stepUp && { stepUp }),
			});
			const written = await store.save(reauth, record, lifetimeMs);
			if (written !== "created") throw new Unavailable("reauth");
			return reauth;
		},
		async take(name, params) {
			// Taken once, whatever the request goes on to need of it.
			const taking =
				name && /^[A-Za-z0-9_-]{43}$/.test(name)
					? await store.update(name, (stored) => {
							const held = fromStored(stored);
							return held && { value: toStored({ ...held, taken: true }) };
						})
					: undefined;
			// Taken here only if this request is the one that marked it taken.
			const before = fromStored(taking?.before);
			const kept = before && !before.taken ? before : undefined;
			return kept?.request === digest(params) ? kept : undefined;
		},
		fresh({ login, maxAgeMs, knownTime }, { authenticatedAt, authenticatedAtUnknown }, taken) {
			if (authenticatedAtUnknown && (login || maxAgeMs !== undefined || knownTime)) return false;
			// Two checks, each on its own. The record shows a login for this request: to the millisecond,
			// as a login the upstream told in whole seconds comes lifted to the start of its round trip.
			const recorded = taken !== undefined && authenticatedAt >= taken.at;
			if (login && !recorded) return false;
			if (maxAgeMs === undefined) return true;
			// max_age=0, which no login's age meets, is met by the record, as prompt=login is.
			if (maxAgeMs === 0) return recorded;
			// Measured now, when asked: a record never stands for an age past it.
			return clock.now() - authenticatedAt <= maxAgeMs;
		},
	};
}

/** The records over the store the assembly gives. */
export const reauthsOver = async (c: BuildContext<unknown>) =>
	reauthsWith({ store: await c.get(reauthStore), clock: c.clock, random: c.random });
