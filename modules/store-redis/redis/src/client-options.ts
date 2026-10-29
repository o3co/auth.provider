import type { TlsOptions } from "@mod/tls-options";
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

/**
 * Why a URL is refused, if it is: the client takes each name of its query as an option, over the
 * ones given it (TLS among them). The reason names each option and where it is written instead,
 * never a value, which may be a password.
 */
export function queryRefusal(url: string): string | undefined {
	const names = [...new Set(new URL(url).searchParams.keys())];
	if (names.length === 0) return undefined;
	const instead = names.map(
		(name) =>
			insteadOf[name] ??
			(/^[A-Za-z][A-Za-z0-9]{0,39}$/.test(name)
				? `${name} is not taken`
				: "an option is not taken"),
	);
	return `redis.url carries no query: write each option as its own setting: ${instead.join("; ")}`;
}

/**
 * The client's options. Over `rediss`, TLS holds to `floor`, its own keys alone and last; over
 * `redis` there is no TLS, which the client would take up for any `tls` given.
 */
export function clientOptions(s: ClientSettings, floor: TlsOptions): RedisOptions {
	const tls =
		new URL(s.url).protocol === "rediss:"
			? { tls: { minVersion: floor.minVersion, ciphers: floor.ciphers } }
			: {};
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
