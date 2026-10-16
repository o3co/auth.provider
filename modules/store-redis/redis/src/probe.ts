import type { Probe } from "@mod/kernel";
import type { Redis } from "ioredis";

/** Passes when every connection answers PING; a dropped one fails at once, having no offline queue. */
export function redisProbe(connections: readonly Redis[]): Probe {
	return {
		name: "redis",
		check: async () => {
			await Promise.all(connections.map((connection) => connection.ping()));
		},
	};
}
