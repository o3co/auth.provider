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
import { confirmationRounds } from "./round/round.ts";
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

/** A user refused keys, in Redis 7.0's or 7.4's words, before a script runs or within it. */
const keysRefused = (message: string) =>
	/no permissions to access (a key|one of the keys)|can't access at least one of the keys/i.test(
		message,
	);
/** A command a script calls refused, in Redis 7.0's or 7.4's words, or one renamed away. */
const refusedInScript = (message: string) =>
	/can't run this command|no permissions to run|unknown (redis )?command/i.test(message);
/** A write refused for want of replicas: no answer on whether the command is allowed. */
const noReplicas = (message: string) => /^NOREPLICAS\b/.test(message);

/**
 * What the server refuses the store for good, each as a problem naming it: a command, or the keys.
 * The confirming connection sends a round's ROLE and INFO, its SET of the confirmation key where
 * replication is declared, and its WAIT, asking for no replica, with replicas; the other runs a
 * script calling every command the scripts call, on keys of the store's own that expire at once,
 * and a SCAN of them. A write refused for want of replicas tells nothing either way, so it is no
 * problem; any other failure is thrown.
 */
export async function refusedCommands(
	client: Redis,
	confirmer: Redis,
	options: Pick<RedisStoreOptions, "prefix" | "replication">,
): Promise<string[]> {
	const { prefix, replication } = options;
	const problems = new Set<string>();
	const storeKeys = `the store's keys (${prefix}:{…})`;
	const judge = (name: string, error: unknown, keys: string) => {
		const message = error instanceof Error ? error.message : String(error);
		if (keysRefused(message)) problems.add(`the server refuses this user ${keys}: allow them`);
		else if (refusedForGood(error) || refusedInScript(message)) {
			problems.add(`the server refuses ${name}: allow it`);
		} else if (!noReplicas(message)) throw error;
	};
	const round = confirmer.pipeline().call("ROLE").info("server");
	const sent = ["ROLE", "INFO"];
	if (replication !== undefined) {
		round.set(`${prefix}:#confirm`, "1", "PX", 60_000);
		sent.push("SET");
	}
	if (replication === "replicas") {
		// Answers within its millisecond, once a confirmation's WAIT before it has.
		round.call("WAIT", 0, 1);
		sent.push("WAIT");
	}
	const replies = (await round.exec()) ?? [];
	sent.forEach((name, at) => {
		const error = replies[at]?.[0];
		if (error) judge(name, error, `the confirmation key (${prefix}:#confirm)`);
	});
	const check = `${prefix}:{#check}`;
	try {
		const failed = (await client.eval(scripts.commands, 2, `${check}:h`, `${check}:s`)) as string[];
		for (let at = 0; at < failed.length; at += 2) {
			judge(String(failed[at]), new Error(String(failed[at + 1])), storeKeys);
		}
	} catch (error) {
		judge("EVAL", error, storeKeys);
	}
	try {
		await client.scan("0", "MATCH", `${literal(check)}:*`, "COUNT", 1);
	} catch (error) {
		judge("SCAN", error, storeKeys);
	}
	return [...problems];
}

const runIdOf = (info: string) => /run_id:(\w+)/.exec(info)?.[1];

/**
 * What a confirmation round and a store script, each run once, tell of the server, as problems: the
 * confirming connection reaching another server than the operations, where replication is declared,
 * as only then does a round run; and a store script the server cannot run, read on a key of the
 * store's own. A replica missing or lagging is none: a write waits for it, and answers unavailable
 * past its timeout. Any other failure, a passing state of the server among them, is thrown.
 */
export async function roundProblems(
	client: Redis,
	confirmer: Redis,
	options: Pick<RedisStoreOptions, "prefix" | "replication">,
): Promise<string[]> {
	const problems: string[] = [];
	if (options.replication !== undefined) {
		// The operations connection is asked before and after the confirming one: a server that
		// changed meanwhile, as in a failover or a restart, tells nothing of where each one goes.
		const before = runIdOf(await client.info("server"));
		const confirming = runIdOf(await confirmer.info("server"));
		const after = runIdOf(await client.info("server"));
		if (before === after && confirming !== before) {
			problems.push(
				"the confirming connection reaches another server than the operations: point both at one server",
			);
		}
	}
	// Each run on a key of the store's own, writing nothing: the batch across only checks a condition.
	const runs: readonly (readonly [string, string, readonly string[]])[] = [
		["read", scripts.read, [`${options.prefix}:{#check}:r`]],
		[
			"batchAcross",
			scripts.batchAcross,
			[
				`${options.prefix}:{#check}:a`,
				JSON.stringify({
					conditions: [{ i: 1, absent: true }],
					writes: [],
					firstMark: 2,
					marks: 0,
				}),
				"",
				"",
				"0",
			],
		],
	];
	for (const [name, script, [key, ...args]] of runs) {
		try {
			await client.eval(script, 1, key ?? "", ...args);
		} catch (error) {
			// The script's own failure, never a passing state of the server (BUSY, LOADING and the like).
			if (!(error instanceof ReplyError) || !/^ERR\b.*script/i.test((error as Error).message))
				throw error;
			problems.push(
				`the server fails a store script (${name}): it lacks what the store's scripts use`,
			);
		}
	}
	return problems;
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
	const { prefix } = options;
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
	const confirmed = confirmationRounds(confirmer, options);
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
				if (!first) {
					// The script answers its own shape; an empty batch committed names no versions.
					const empty = await run(scripts.deadlineOnly, [], [options?.deadline ?? ""]);
					return empty.kind === "committed" ? { kind: "committed", versions: [] } : empty;
				}
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
			batchAcross: async (conditions, writes, options) => {
				const keys = [...conditions.map((c) => c.key), ...writes.map((w) => w.key)];
				const [first] = keys;
				if (!first) {
					const empty = await run(scripts.deadlineOnly, [], [options?.deadline ?? ""]);
					return empty.kind === "committed" ? { kind: "committed", versions: [] } : empty;
				}
				const names = [...new Set(keys.map(valueKey))];
				const index = (key: Key) => names.indexOf(valueKey(key)) + 1;
				const versionKeys = [...new Set(writes.map((w) => versionKey(w.key)))];
				const markKeys = [...new Set(keys.map((k) => markKey(k, options?.idempotency)))];
				const spec = {
					conditions: conditions.map((c) =>
						"absent" in c
							? { i: index(c.key), absent: true }
							: { i: index(c.key), version: c.version },
					),
					writes: writes.map((w) => {
						if ("remove" in w) return { i: index(w.key), remove: true };
						const [kind, arg] = expiryArgs(w.expiry);
						const v = names.length + versionKeys.indexOf(versionKey(w.key)) + 1;
						return { i: index(w.key), v, put: canonicalJson(w.put), kind, arg };
					}),
					firstMark: names.length + versionKeys.length + 1,
					marks: markKeys.length,
				};
				const request = idempotencyRequest("batchAcross", keys, [
					conditions.map((c) => ("absent" in c ? { absent: true } : { version: c.version })),
					writes.map((w) => ("remove" in w ? null : [w.put, w.expiry])),
				]);
				const answer = await run(
					scripts.batchAcross,
					[...names, ...versionKeys, ...markKeys],
					[JSON.stringify(spec), options?.deadline ?? "", digest(request), marked(options)],
				);
				// The spaces share their guarantees, so the first key's tells how to confirm.
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
