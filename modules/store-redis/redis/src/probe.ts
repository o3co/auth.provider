import type { Log, Probe } from "@mod/kernel";
import type { Redis } from "ioredis";

/**
 * Passes when every connection answers PING and the server still gives what boot checked; a
 * dropped connection fails at once, having no offline queue. `unmet` names what no longer holds.
 */
export function redisProbe(
	connections: readonly Redis[],
	unmet: () => Promise<readonly string[]>,
	log: Log,
): Probe {
	let told = "";
	return {
		name: "redis",
		check: async () => {
			await Promise.all(connections.map((connection) => connection.ping()));
			const problems = (await unmet()).join("; ");
			// Told when it changes, not on every probe.
			if (problems !== told && problems !== "") log.warn("redis.settings_unmet", { problems });
			told = problems;
			if (problems !== "") throw new Error("redis: the server no longer gives what boot checked");
		},
	};
}
