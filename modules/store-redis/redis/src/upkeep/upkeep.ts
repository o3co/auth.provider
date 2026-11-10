import type { Random } from "@mod/kernel";
import { Unavailable } from "@mod/kernel";
import {
	type Control,
	canonicalJson,
	checkedUpkeep,
	type Guarantee,
	type Honours,
	type Json,
	type Mark,
	noSubjectData,
	type Space,
	type StoreControl,
	type StoreUpkeep,
} from "@mod/store";
import { list } from "../answer/answer.ts";
import type { keysUnder } from "../keys.ts";
import type { scriptsOn, serverOf, Taken } from "../redis-store.ts";
import { changing, prelude } from "../scripts.ts";

/** How many keys SCAN is asked for at a time by `sweep`. */
const sweepPage = 200;

/** KEYS: control record, ledger. The record and the ledger as they stand, with no epoch check. */
const read = `${prelude}
local held = redis.call('HMGET', KEYS[1], 'epoch', 'maintenance', 'requires', 'marks')
return out(cjson.encode({
  epoch = held[1] or '', maintenance = held[2] == '1', requires = held[3] or '[]',
  marks = held[4] or '{}', ledger = redis.call('GET', KEYS[2]) or '{}'
}))
`;

/**
 * KEYS: control record, ledger. ARGV: what to do, its arguments, then the epoch check's. The
 * control record is a hash (epoch, maintenance, requires and marks as JSON); the ledger, one JSON
 * map of each space's fields. `require` and `retire` hold only under the maintenance key.
 */
const change = `${changing}
local control, ledger, op = KEYS[1], KEYS[2], ARGV[1]
local answer
if op == 'mark' then
  local marks = cjson.decode(redis.call('HGET', control, 'marks') or '{}')
  marks[ARGV[2]] = {value = ARGV[3], epoch = held_epoch}
  redis.call('HSET', control, 'marks', cjson.encode(marks))
  answer = {kind = 'marked'}
elseif op == 'enter' then
  redis.call('HSET', control, 'epoch', ARGV[2], 'maintenance', '1')
  answer = {kind = 'entered', epoch = ARGV[2]}
elseif op == 'leave' then
  redis.call('HSET', control, 'maintenance', '0')
  answer = {kind = 'left'}
elseif op == 'keep' then
  local held = cjson.decode(redis.call('GET', ledger) or '{}')
  for name, ever in pairs(cjson.decode(ARGV[2])) do
    local before = held[name]
    held[name] = {subjectDataEver = (before ~= nil and before.subjectDataEver) or ever}
  end
  redis.call('SET', ledger, cjson.encode(held))
  answer = {kind = 'kept'}
elseif redis.call('HGET', control, 'maintenance') ~= '1' then
  answer = {kind = 'not-in-maintenance'}
elseif op == 'require' then
  redis.call('HSET', control, 'requires', ARGV[2])
  answer = {kind = 'required'}
elseif ARGV[3] == '1' then
  answer = {kind = 'declared'}
else
  local held = cjson.decode(redis.call('GET', ledger) or '{}')
  if held[ARGV[2]] == nil then
    answer = {kind = 'missing'}
  else
    held[ARGV[2]] = nil
    redis.call('SET', ledger, cjson.encode(held))
    answer = {kind = 'retired'}
  end
end
return out(cjson.encode(answer))
`;

/** No KEYS. ARGV: cursor, pattern, count, then the epoch check's. Removes each expired key met. */
const sweep = `${changing}
local reply = redis.call('SCAN', ARGV[1], 'MATCH', ARGV[2], 'COUNT', ARGV[3])
local live = {}
for _, key in ipairs(reply[2]) do
  local expires = redis.call('PEXPIRETIME', key)
  if expires >= 0 and expires <= now then redis.call('DEL', key) else table.insert(live, key) end
end
return out(cjson.encode({cursor = reply[1], keys = live, n = #live}))
`;

export interface UpkeepParts {
	readonly run: ReturnType<typeof scriptsOn>;
	readonly serverOf: typeof serverOf;
	/** A confirmation round's server, where replication is declared; undefined otherwise. */
	readonly confirmed: (() => Promise<string>) | undefined;
	readonly keys: ReturnType<typeof keysUnder>;
	readonly declared: readonly Space[];
	readonly taken: Taken;
	readonly random: Random;
	readonly honours: (guarantees: readonly Guarantee[]) => Promise<Honours>;
}

/**
 * The control record and the ledger on Redis: the reads, the upkeep, what a process does as it
 * starts (`start`), and whether the record's epoch moved from the one the process took (`moved`).
 */
export function redisUpkeepWith(parts: UpkeepParts) {
	const { run, keys, declared, taken } = parts;
	const both = [keys.controlKey, keys.ledgerKey];
	const fenced = (args: string[]) => [...args, keys.controlKey, taken.epoch];
	/** Confirms an answer on the server that computed it, where replication is declared. */
	const confirm = async <A extends object>(answer: A): Promise<A> => {
		if (parts.confirmed && (await parts.confirmed()) !== parts.serverOf(answer)) {
			throw new Unavailable("store");
		}
		return answer;
	};
	const changed = async (op: string, ...args: string[]) =>
		(await confirm(await run(change, both, fenced([op, ...args])))) as { kind: string };
	/** The record and the ledger, confirmed unless `confirmed` is false. */
	const readAll = async (confirmed = true) => {
		const answer = await run(read, both, []);
		const held = confirmed ? await confirm(answer) : answer;
		return {
			epoch: held.epoch as string,
			maintenance: held.maintenance === true,
			requires: JSON.parse(held.requires as string) as string[],
			marks: JSON.parse(held.marks as string) as Record<string, { value: string; epoch: string }>,
			ledger: JSON.parse(held.ledger as string) as Record<string, { subjectDataEver: boolean }>,
		};
	};
	const known = new Set(declared.map((space) => space.name));
	const control: StoreControl = {
		control: async () => {
			const held = await readAll();
			const marks: Record<string, Mark> = {};
			for (const [name, mark] of Object.entries(held.marks)) {
				marks[name] = { value: JSON.parse(mark.value) as Json, epoch: mark.epoch || null };
			}
			const record: Control = {
				epoch: held.epoch || null,
				maintenance: held.maintenance,
				requires: held.requires,
				marks,
			};
			return Object.freeze(record);
		},
	};
	const upkeep: StoreUpkeep = {
		mark: async (name, value) => {
			await changed("mark", name, canonicalJson(value));
			return { kind: "marked" };
		},
		require: async (names) =>
			(await changed("require", JSON.stringify(names))) as Awaited<
				ReturnType<StoreUpkeep["require"]>
			>,
		enterMaintenance: async () => {
			const epoch = Buffer.from(parts.random.bytes(16)).toString("hex");
			await changed("enter", epoch);
			taken.epoch = epoch;
			return { kind: "entered", epoch };
		},
		leaveMaintenance: async () => {
			await changed("leave");
			return { kind: "left" };
		},
		kept: async () =>
			Object.freeze(
				Object.entries((await readAll()).ledger).map(([name, fields]) => ({
					name,
					subjectDataEver: fields.subjectDataEver === true,
				})),
			),
		retire: async (name) =>
			(await changed("retire", name, known.has(name) ? "1" : "0")) as Awaited<
				ReturnType<StoreUpkeep["retire"]>
			>,
		honours: (guarantees) => parts.honours(guarantees),
		sweep: async (space, cursor) => {
			const answer = await run(
				sweep,
				[],
				fenced([cursor ?? "0", keys.spaceValues(space), String(sweepPage)]),
			);
			// Removing is writing: confirmed where the space's writes are.
			if (space.guarantees.includes("replicated")) await confirm(answer);
			const found = list<string>(answer.keys, answer.n as number).map((at) =>
				keys.keyAt(space, at),
			);
			const server = String(parts.serverOf(answer));
			const next = String(answer.cursor);
			return next === "0" ? { keys: found, server } : { keys: found, cursor: next, server };
		},
	};
	const entries = JSON.stringify(
		Object.fromEntries(declared.map((space) => [space.name, space.subjectData !== noSubjectData])),
	);
	/** Adds each declared space to the ledger, unconfirmed: any later confirmed write confirms it. */
	const keep = () => run(change, both, fenced(["keep", entries]));
	/**
	 * As a process starts: takes the record's epoch, then adds each declared space to the ledger
	 * before any other change, neither waiting for replicas, so a start with none yet still boots;
	 * a start that cannot is refused by its caller.
	 */
	const start = async () => {
		taken.epoch = (await readAll(false)).epoch;
		await keep();
	};
	/**
	 * What no longer holds of the process's start: the record's epoch moved from the one it took;
	 * or the ledger lacks a declared space, as a failover can lose the unconfirmed entry, which is
	 * then added again.
	 */
	const recheck = async (): Promise<string[]> => {
		const held = await readAll(false);
		if (held.epoch !== taken.epoch) return ["the store's epoch moved since this process started"];
		if (declared.every((space) => Object.hasOwn(held.ledger, space.name))) return [];
		await keep();
		return [];
	};
	return { control, upkeep: checkedUpkeep(upkeep, declared), start, recheck };
}
