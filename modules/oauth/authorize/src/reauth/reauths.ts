import { createHash } from "node:crypto";
import { type BuildContext, type Clock, type Random, Unavailable } from "@mod/kernel";
import type { AuthContext } from "@mod/session";
import type { Settings } from "../section.ts";
import { type ReauthStore, reauthStore } from "../store.ts";
import { fromStored, type Reauth, toStored } from "./reauth.ts";

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

/** Re-authentications asked for one request (its parameters, each one's first value), each taken once. */
export interface Reauths {
	/** Keeps a new record for the request, from a login at `at` on, and gives its name. */
	remember(params: ReadonlyMap<string, string>, at: number, stepUp?: true): Promise<string>;
	/** Takes the named record; it counts only when this call took it and it was made for the request. */
	take(name: string | undefined, params: ReadonlyMap<string, string>): Promise<Reauth | undefined>;
	/**
	 * Whether the session's login is fresh enough for `prompt=login` and `max_age`, and its time known
	 * when one is needed; an unknown time never is.
	 */
	fresh(
		asked: {
			readonly login: boolean;
			readonly maxAgeMs: number | undefined;
			/** An essential `auth_time` was asked. */
			readonly knownTime: boolean;
		},
		context: Pick<AuthContext, "authenticatedAt" | "authenticatedAtUnknown">,
		taken: Reauth | undefined,
	): boolean;
}

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
			if (written !== "created") throw new Unavailable("authorize");
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
			if (!login && maxAgeMs === undefined) return true;
			if (!login && maxAgeMs !== undefined && clock.now() - authenticatedAt <= maxAgeMs)
				return true;
			// In whole seconds: an authentication time may be known only to the second.
			return (
				taken !== undefined && Math.floor(authenticatedAt / 1000) >= Math.floor(taken.at / 1000)
			);
		},
	};
}

/** The records over the store the assembly gives. */
export const reauthsOver = async (c: BuildContext<Settings>) =>
	reauthsWith({ store: await c.get(reauthStore), clock: c.clock, random: c.random });
