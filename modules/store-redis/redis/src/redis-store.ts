import { createHash } from "node:crypto";
import { Unavailable } from "@mod/kernel";
import {
	canonicalJson,
	checkedStore,
	codePointOrder,
	type Entry,
	type Expiry,
	idempotencyRequest,
	type Json,
	type Key,
	type Space,
	type Store,
} from "@mod/store";
import type { Redis } from "ioredis";
import { sharedRounds } from "./rounds.ts";
import * as scripts from "./scripts.ts";

type Raw = { value: string; version: string; expiresAt: string | null };

const enc = encodeURIComponent;

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
	const setKey = (key: Key) => `${slot(key)}:s:${enc(key.name)}`;
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
		mode: "put" | "putIfAbsent" | "replaceIf",
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
			getMany: async (keys) => {
				samePartition(keys);
				const read = await run(scripts.read, keys.map(valueKey), []);
				const [first] = keys;
				if (first) await confirm(first, read);
				return { entries: list<Raw | false>(read.entries, read.n).map(entry), now: read.now };
			},
			put: (key, value, options) => writeWith("put", key, value, "", options),
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
			setAdd: async (key, member, score, options) => {
				const [kind, arg] = expiryArgs(options.expiry);
				const answer = await run(
					scripts.setAdd,
					[setKey(key)],
					[member, score, options.cap, kind, arg],
				);
				// A set's add always writes.
				await confirmOn(key, true, answer);
				return { evicted: list<string>(answer.evicted, answer.n) };
			},
			setMembers: async (key) => {
				const answer = await confirm(key, await run(scripts.setMembers, [setKey(key)], []));
				const flat: string[] = Array.isArray(answer.members) ? answer.members : [];
				const members = [];
				for (let i = 0; i < flat.length; i += 2) {
					members.push({ member: flat[i] as string, score: Number(flat[i + 1]) });
				}
				members.sort((a, b) => codePointOrder(a.member, b.member));
				return { members, now: answer.now };
			},
			setRemove: async (key, member) => {
				await confirm(key, await run(scripts.setRemove, [setKey(key)], [member]));
			},
			now: async () => (await run(scripts.now, [], [])).now as number,
		},
		declared,
	);
}
