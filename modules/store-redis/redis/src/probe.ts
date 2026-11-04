import type { Clock, Log, Probe } from "@mod/kernel";
import type { Redis } from "ioredis";

/** How long a start of `unmet` serves later probes, counted from that start. */
const recheckMs = 1000;

/**
 * Passes when every connection answers PING, on every run, and the server still gives what boot
 * checked; a dropped connection fails at once, having no offline queue. `unmet` names what no longer
 * holds, and starts at most once per `recheckMs`: a later probe within that time reads what it
 * answered, pass or fail, and joins it while it runs.
 */
export function redisProbe(
	connections: readonly Redis[],
	unmet: () => Promise<readonly string[]>,
	log: Log,
	clock: Clock,
): Probe {
	let told = "";
	let last:
		| { readonly started: number; readonly answer: Promise<readonly string[]>; ended?: true }
		| undefined;
	const checked = () => {
		const now = clock.now();
		// A clock set back runs anew.
		const fresh = last && now >= last.started && now - last.started < recheckMs;
		if (last && (!last.ended || fresh)) return last.answer;
		const run: NonNullable<typeof last> = { started: now, answer: unmet() };
		const ended = () => {
			run.ended = true;
		};
		run.answer.then(ended, ended);
		last = run;
		return run.answer;
	};
	return {
		name: "redis",
		check: async () => {
			await Promise.all(connections.map((connection) => connection.ping()));
			const problems = (await checked()).join("; ");
			// Told when it changes, not on every probe.
			if (problems !== told && problems !== "") log.warn("redis.settings_unmet", { problems });
			told = problems;
			if (problems !== "") throw new Error("redis: the server no longer gives what boot checked");
		},
	};
}
