import { heldToFloor, type TlsOptions } from "@mod/tls-options";
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

/** Whether `DEBUG` turns on the client's `ioredis:redis` log, which writes AUTH's password, read as the `debug` library reads it. */
export function clientDebugs(debug: string | undefined): boolean {
	const names = (debug ?? "").split(/[\s,]+/).filter((name) => name !== "");
	const matches = (pattern: string) =>
		new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*?")}$`).test(
			"ioredis:redis",
		);
	if (names.some((name) => name.startsWith("-") && matches(name.slice(1)))) return false;
	return names.some((name) => !name.startsWith("-") && matches(name));
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
