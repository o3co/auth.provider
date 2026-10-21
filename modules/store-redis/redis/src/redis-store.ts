import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import {
	canonicalJson,
	checkedStore,
	type Entry,
	type Expiry,
	idempotencyRequest,
	type Json,
	type Key,
	type Space,
	type Store,
} from "@mod/store";
import { type Redis, ReplyError } from "ioredis";
import { sharedRounds } from "./rounds.ts";
import * as scripts from "./scripts.ts";

type Raw = { value: string; version: string; expiresAt: string | null };

const enc = encodeURIComponent;
/** A text matched literally by SCAN's pattern. */
const literal = (text: string) => text.replace(/[*?[\]\\]/g, (c) => `\\${c}`);

/** cjson turns empty or sparse Lua arrays into objects; rebuild them by count. */
function list<T>(value: unknown, n: number): T[] {
	return Array.from({ length: n }, (_, i) => (value as Record<number, T>)[i] as T);
}

/** Script answers carry numbers as strings; turn the known ones back into numbers (the fields scripts.ts answers). */
function numbers<A extends Record<string, unknown>>(answer: A): A {
	const out: Record<string, unknown> = { ...answer };
	for (const field of ["now", "remainingMs", "resetAt", "count"]) {
		if (typeof out[field] === "string") out[field] = Number(out[field]);
	}
	return out as A;
}

const digest = (request: string) => createHash("sha256").update(request).digest("hex");
/** Where a script answer records the server it ran on, out of sight of the callers. */
const servedBy = Symbol("served by");
const writtenKinds = new Set(["written", "removed", "taken", "committed", "counted"]);

export interface RedisStoreOptions {
	readonly prefix: string;
	readonly replicationTimeoutMs: number;
	/** What the operator declared: no failover at all, or replicas that must take every write. */
	readonly replication: "none" | "replicas" | undefined;
}

/** Whether the server refuses a command for good, for want of permission or of the command; any other error is no answer. */
export const refusedForGood = (error: unknown) =>
	error instanceof ReplyError &&
	/^(NOPERM|ERR unknown (sub)?command)\b/i.test((error as Error).message);

/** A script's refusal of what it calls, as Redis words it: the script ran, a command in it did not. */
const refusedInScript = (error: unknown) =>
	error instanceof ReplyError &&
	/script/i.test((error as Error).message) &&
	/NOPERM|unknown (redis )?command/i.test((error as Error).message);

/**
 * The commands the store sends that the server refuses for good, by name: a round's ROLE and INFO,
 * and its SET and WAIT where replication is declared, on the confirming connection; EVAL, and what
 * every script calls, on the other. One trip each, writing only the confirmation key; WAIT asks for
 * no replica, so it answers at once whatever replicas there are. Any other failure is thrown.
 */
export async function refusedCommands(
	client: Redis,
	confirmer: Redis,
	options: Pick<RedisStoreOptions, "prefix" | "replication">,
): Promise<string[]> {
	const confirming = options.replication !== undefined;
	const sent = confirming ? ["ROLE", "INFO", "SET", "WAIT"] : ["ROLE", "INFO"];
	const round = confirmer.pipeline().call("ROLE").info("server");
	if (confirming) round.set(`${options.prefix}:#confirm`, "1", "PX", 60_000).call("WAIT", 0, 1);
	const replies = (await round.exec()) ?? [];
	const failed = replies.find(([error]) => error && !refusedForGood(error));
	if (failed) throw failed[0];
	const refused = sent.filter((_, at) => refusedForGood(replies[at]?.[0]));
	try {
		await client.eval(scripts.commands, 1, `${options.prefix}:#confirm`);
	} catch (error) {
		if (refusedInScript(error)) {
			refused.push("a command a script calls (TIME, INFO or PEXPIRETIME)");
		} else if (refusedForGood(error)) refused.push("EVAL");
		else throw error;
	}
	return refused;
}

/**
 * `client` serves the operations; `confirmer` is a connection of its own for confirming
 * replication, so a WAIT never holds up the other commands.
 */
export function redisStore(
	client: Redis,
	confirmer: Redis,
	options: RedisStoreOptions,
	declared: readonly Space[],
): Store {
	const { prefix, replicationTimeoutMs } = options;
	const slot = (key: Key) => `${prefix}:{${enc(key.space.name)}:${enc(key.partition)}}`;
	const valueKey = (key: Key) => `${slot(key)}:v:${enc(key.name)}`;
	const counterKey = (key: Key) => `${slot(key)}:c:${enc(key.name)}`;
	const versionKey = (key: Key) => `${slot(key)}:#version`;
	const markKey = (key: Key, mark: string | undefined) => `${slot(key)}:#mark:${enc(mark ?? "")}`;
	/** Runs a script; every answer comes with the run id of the server that computed it. */
	const run = async (script: string, keys: string[], args: (string | number)[]) => {
		let reply: unknown;
		try {
			reply = await client.eval(script, keys.length, ...keys, ...args);
		} catch {
			throw new Unavailable("store");
		}
		const text = String(reply);
		const split = text.indexOf("\n");
		const answer = numbers(JSON.parse(text.slice(split + 1)));
		Object.defineProperty(answer, servedBy, { value: text.slice(0, split), enumerable: false });
		return answer;
	};
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
			const replies = await confirmer
				.pipeline()
				.call("ROLE")
				.info("server")
				.set(`${prefix}:#confirm`, "1", "PX", 60_000)
				.exec();
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
	const confirmed = sharedRounds(round);
	/**
	 * Replicated spaces confirm what they wrote; spaces asking for confirmed reads confirm every
	 * answer. The round must have run on the server that computed the answer.
	 */
	const confirmOn = async (key: Key, wrote: boolean, answer: object) => {
		const guarantees = key.space.guarantees;
		const needed =
			guarantees.includes("confirmed-reads") || (guarantees.includes("replicated") && wrote);
		if (!needed) return;
		const server = await confirmed();
		if (server !== (answer as Record<symbol, unknown>)[servedBy]) throw new Unavailable("store");
	};
	const confirm = async <A extends { kind: string }>(key: Key, answer: A): Promise<A> => {
		await confirmOn(key, writtenKinds.has(answer.kind), answer);
		return answer;
	};
	const expiryArgs = (expiry: Expiry): [string, string] => {
		if (expiry.kind === "after" || expiry.kind === "extend")
			return [expiry.kind, String(expiry.ms)];
		if (expiry.kind === "at") return ["at", String(expiry.at)];
		return [expiry.kind, ""];
	};
	const entry = (raw: Raw | false | undefined): Entry | null =>
		raw
			? Object.freeze({
					value: JSON.parse(raw.value) as Json,
					version: raw.version,
					expiresAt: raw.expiresAt === null ? null : Number(raw.expiresAt),
				})
			: null;
	const samePartition = (keys: readonly Key[]) => {
		if (new Set(keys.map(slot)).size > 1) throw new Error("keys span more than one partition");
	};
	const marked = (options: { idempotency?: string } | undefined) =>
		options?.idempotency ? "1" : "0";
	const writeWith = async (
		mode: "putIfAbsent" | "replaceIf",
		key: Key,
		value: Json,
		expected: string,
		options: { expiry: Expiry; deadline?: number; idempotency?: string },
	) => {
		const [kind, arg] = expiryArgs(options.expiry);
		const args: Json[] =
			mode === "replaceIf" ? [expected, value, options.expiry] : [value, options.expiry];
		const answer = await run(
			scripts.write,
			[valueKey(key), versionKey(key), markKey(key, options.idempotency)],
			[
				mode,
				canonicalJson(value),
				expected,
				kind,
				arg,
				options.deadline ?? "",
				digest(idempotencyRequest(mode, [key], args)),
				marked(options),
			],
		);
		return confirm(key, answer);
	};

	return checkedStore(
		{
			get: async (key) => {
				const read = await confirm(key, await run(scripts.read, [valueKey(key)], []));
				return { entry: entry(list<Raw | false>(read.entries, 1)[0]), now: read.now };
			},
			putIfAbsent: (key, value, options) => writeWith("putIfAbsent", key, value, "", options),
			replaceIf: (key, version, value, options) =>
				writeWith("replaceIf", key, value, version, options),
			removeIf: async (key, expected, options) => {
				const by = "version" in expected ? "version" : "value";
				const target = "version" in expected ? expected.version : canonicalJson(expected.value);
				const answer = await run(
					scripts.removeIf,
					[valueKey(key), markKey(key, options?.idempotency)],
					[
						by,
						target,
						options?.deadline ?? "",
						digest(idempotencyRequest("removeIf", [key], [expected])),
						marked(options),
					],
				);
				await confirm(key, answer);
				return answer.kind === "removed"
					? { kind: "removed", old: entry(answer.old) as Entry }
					: answer;
			},
			take: async (key, options) => {
				const answer = await run(
					scripts.take,
					[valueKey(key), markKey(key, options?.idempotency)],
					[options?.deadline ?? "", digest(idempotencyRequest("take", [key], [])), marked(options)],
				);
				await confirm(key, answer);
				return answer.kind === "taken"
					? { kind: "taken", entry: entry(answer.entry) as Entry }
					: answer;
			},
			batch: async (conditions, writes, options) => {
				const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
				samePartition(keys);
				const [first] = keys;
				if (!first) return run(scripts.deadlineOnly, [], [options?.deadline ?? ""]);
				const names = [...new Set(keys.map(valueKey))];
				const index = (key: Key) => names.indexOf(valueKey(key)) + 1;
				const spec = {
					conditions: conditions.map((c) =>
						"absent" in c
							? { i: index(c.key), absent: true }
							: { i: index(c.key), version: c.version },
					),
					writes: writes.map((w) => {
						if ("remove" in w) return { i: index(w.key), remove: true };
						const [kind, arg] = expiryArgs(w.expiry);
						return { i: index(w.key), put: canonicalJson(w.put), kind, arg };
					}),
				};
				const request = idempotencyRequest("batch", keys, [
					conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
					writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
				]);
				const answer = await run(
					scripts.batch,
					[...names, versionKey(first), markKey(first, options?.idempotency)],
					[JSON.stringify(spec), options?.deadline ?? "", digest(request), marked(options)],
				);
				await confirm(first, answer);
				return answer.kind === "committed"
					? { kind: "committed", versions: list<string | null>(answer.versions, answer.n) }
					: answer;
			},
			count: async (key, window, options) => {
				const answer = await run(
					scripts.count,
					[counterKey(key), markKey(key, options?.idempotency)],
					[
						window.ms,
						window.limit,
						options?.deadline ?? "",
						digest(idempotencyRequest("count", [key], [window.ms, window.limit])),
						marked(options),
					],
				);
				return confirm(key, answer);
			},
			now: async () => (await run(scripts.now, [], [])).now as number,
			scan: async (space, cursor) => {
				const head = `${prefix}:{${enc(space.name)}:`;
				let reply: [string, string[]];
				try {
					reply = await client.scan(cursor ?? "0", "MATCH", `${literal(head)}*}:v:*`, "COUNT", 200);
				} catch {
					throw new Unavailable("store");
				}
				const [next, found] = reply;
				const keys = found.map((at) => {
					const [partition = "", name = ""] = at.slice(head.length).split("}:v:");
					return {
						space,
						partition: decodeURIComponent(partition),
						name: decodeURIComponent(name),
					};
				});
				return next === "0" ? { keys } : { keys, cursor: next };
			},
		},
		declared,
	);
}
