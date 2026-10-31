import { Unavailable } from "@mod/kernel";
import type { Redis } from "ioredis";
import type { RedisStoreOptions } from "../redis-store.ts";
import { sharedRounds } from "./rounds.ts";

/** How long the confirmation key lives once written. */
const confirmKeyMs = 60_000;

/**
 * One trip on the confirming connection: ROLE, INFO server and, but where `write` is false, the
 * confirmation key; the boot check and every confirmation round send it alike.
 */
export const confirmationPipeline = (confirmer: Redis, prefix: string, write = true) => {
	const asked = confirmer.pipeline().call("ROLE").info("server");
	return write ? asked.set(`${prefix}:#confirm`, "1", "PX", confirmKeyMs) : asked;
};

/**
 * Confirmations on the confirming connection: each answers the run id of the server it confirmed
 * on, or throws Unavailable; one asked while a round runs rides on the next.
 */
export function confirmationRounds(
	confirmer: Redis,
	options: Pick<RedisStoreOptions, "prefix" | "replicationTimeoutMs" | "replication">,
): () => Promise<string> {
	const { prefix, replicationTimeoutMs } = options;
	/**
	 * One confirmation round: in one trip, learn the replicas and the server, and write a key on
	 * the confirming connection; then wait until every replica online now has it. Replication is
	 * ordered, so a round covers everything the primary did before. WAIT waits only for its own
	 * connection's writes, hence the key; and a connection of its own keeps WAIT from holding other
	 * commands. The confirming connection must talk to the same server as the operations (a DNS or
	 * load-balancer change can part them), and the replicas must match what the operator declared.
	 */
	const round = async (): Promise<string> => {
		try {
			const replies = await confirmationPipeline(confirmer, prefix).exec();
			if (!replies || replies.some(([error]) => error)) throw new Error("confirmation failed");
			const role = replies[0]?.[1] as [string, number, unknown[]];
			const server = /run_id:(\w+)/.exec(String(replies[1]?.[1]))?.[1];
			if (role[0] !== "master" || server === undefined) throw new Error("not a primary");
			const replicas = Array.isArray(role[2]) ? role[2].length : 0;
			if (options.replication === "none") {
				if (replicas === 0) return server;
				throw new Error("replicas seen where none were declared");
			}
			// A primary cut off from the others also sees none, and what it confirmed would be lost.
			if (replicas === 0) throw new Error("no replica to confirm with");
			const acknowledged = Number(await confirmer.call("WAIT", replicas, replicationTimeoutMs));
			if (acknowledged >= replicas) return server;
		} catch {}
		throw new Unavailable("store");
	};
	return sharedRounds(round);
}
