import { heldToFloor, type TlsOptions } from "@mod/tls-options";
import { isLoopbackName } from "@mod/url-setting";
import type { RedisOptions } from "ioredis";

/** What of the section the client's options are made from. */
export interface ClientSettings {
	readonly url: string;
	readonly "connect-timeout": number;
	readonly "command-timeout": number;
	readonly "address-family"?: "ipv4" | "ipv6" | undefined;
}

/** Where each option the client would read from a URL's query is written instead. */
const insteadOf: Readonly<Record<string, string>> = {
	db: "db as the URL's path (/2)",
	username: "username in the URL (user:password@host)",
	password: "password in the URL (user:password@host)",
	tls: "tls as rediss:// with the tls-options section, the server's authority in the platform's store",
	family: "family as redis.address-family (ipv4 or ipv6)",
	connectTimeout: "connectTimeout as redis.connect-timeout",
	commandTimeout: "commandTimeout as redis.command-timeout",
};

/** Why a URL with a query, an empty one too, is refused, as the client reads options from it; never a value. */
export function queryRefusal(url: string): string | undefined {
	if (!url.split("#")[0]?.includes("?")) return undefined;
	const lead = "redis.url carries no query: write each option as its own setting";
	const names = [...new Set(new URL(url).searchParams.keys())];
	if (names.length === 0) return `${lead}, and take out the ?`;
	const instead = [...new Set(names.map((name) => insteadOf[name] ?? "an option is not taken"))];
	return `${lead}: ${instead.join("; ")}`;
}

/** Whether the URL reaches Redis in the clear off this host: `redis`, at a host not loopback by its name. */
export const inTheClear = (url: string): boolean => {
	const { protocol, hostname } = new URL(url);
	return protocol === "redis:" && !isLoopbackName(hostname);
};

/** Where the client's logs are named: `ioredis:redis` writes AUTH's password, and each writes to stderr. */
const clientLogs = "ioredis:";

/** A `debug` template's places (`*` any run of characters, all else itself), with each `*` passed too, as it may take none. */
function past(template: string, places: readonly number[]): number[] {
	const all = new Set<number>();
	for (let at of places) {
		all.add(at);
		while (template[at] === "*") all.add(++at);
	}
	return [...all].sort((a, b) => a - b);
}

/** A template's places after one more character. */
const step = (template: string, places: readonly number[], char: string): number[] =>
	past(
		template,
		places.flatMap((at) => (template[at] === "*" ? [at] : template[at] === char ? [at + 1] : [])),
	);

/**
 * Whether `DEBUG` turns on any of the client's `ioredis:` logs, read as the `debug` library reads it:
 * a namespace a negation names is off, one another template names on. Every name under `ioredis:` is
 * tried, a character at a time, each template's places held, until one is on or no other is left.
 */
export function clientDebugs(debug: string | undefined): boolean {
	const templates = (debug ?? "").split(/[\s,]+/).filter((t) => t !== "");
	const names = templates.filter((t) => !t.startsWith("-"));
	const all = [...names, ...templates.filter((t) => t.startsWith("-")).map((t) => t.slice(1))];
	// A character no template names stands for every one such.
	const chars = [...new Set([...all.join("").replaceAll("*", ""), "\0"])];
	const start = all.map((t) =>
		[...clientLogs].reduce((at, char) => step(t, at, char), past(t, [0])),
	);
	const seen = new Set<string>();
	// No log is named `ioredis:` alone.
	const queue = chars.map((char) => start.map((at, i) => step(all[i] ?? "", at, char)));
	for (const places of queue) {
		const key = JSON.stringify(places);
		if (seen.has(key)) continue;
		seen.add(key);
		const ends = places.map((at, i) => at.includes(all[i]?.length ?? -1));
		const on = ends.slice(0, names.length).some(Boolean);
		if (on && !ends.slice(names.length).some(Boolean)) return true;
		if (places.slice(0, names.length).every((at) => at.length === 0)) continue;
		for (const char of chars) queue.push(places.map((at, i) => step(all[i] ?? "", at, char)));
	}
	return false;
}

/**
 * The client's options. Over `rediss`, TLS is held to `floor` (`heldToFloor`: its own keys alone, as
 * `tls-options` knows them); over `redis` there is no TLS, which the client would take up for any
 * `tls` given.
 */
export function clientOptions(s: ClientSettings, floor: TlsOptions): RedisOptions {
	const tls = new URL(s.url).protocol === "rediss:" ? { tls: heldToFloor(floor, {}) } : {};
	const family = s["address-family"];
	return {
		lazyConnect: true,
		...(family === undefined ? {} : { family: family === "ipv4" ? 4 : 6 }),
		connectTimeout: s["connect-timeout"],
		maxRetriesPerRequest: 0,
		enableOfflineQueue: false,
		// A command whose reply was lost must not be sent again on a new connection: a resent
		// WAIT would confirm nothing, and a resent script would run twice.
		autoResendUnfulfilledCommands: false,
		commandTimeout: s["command-timeout"],
		...tls,
	};
}
