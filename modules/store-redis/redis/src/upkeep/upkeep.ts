import type { Random } from "@mod/kernel";
import { BuildRefused, Unavailable } from "@mod/kernel";
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
	type UpkeepImplementation,
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
  -- Every declaration added is a new generation, the entry's subjectDataEver kept.
  local held = cjson.decode(redis.call('GET', ledger) or '{}')
  for name, ever in pairs(cjson.decode(ARGV[2])) do
    local before = held[name]
    held[name] = {subjectDataEver = (before ~= nil and before.subjectDataEver) or ever, generation = ARGV[3]}
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
  elseif ARGV[4] ~= '' and (held[ARGV[2]].generation or 'none') ~= ARGV[4] then
    answer = {kind = 'redeclared'}
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
  -- -2: gone already; at or before now: expired, deleted here; else live.
  if expires >= 0 and expires <= now then redis.call('DEL', key)
  elseif expires ~= -2 then table.insert(live, key) end
end
return out(cjson.encode({cursor = reply[1], keys = live, n = #live}))
`;

/** KEYS: control, ledger. ARGV: declared, name, SCAN cursor, pattern, count, fence. A kept walk's page, in one script. */
const keptWalk = `${changing}
local control, ledger = KEYS[1], KEYS[2]
if redis.call('HGET', control, 'maintenance') ~= '1' then return out(cjson.encode({kind = 'not-in-maintenance'})) end
if ARGV[1] == '1' then return out(cjson.encode({kind = 'declared'})) end
local entry = cjson.decode(redis.call('GET', ledger) or '{}')[ARGV[2]]
if entry == nil then return out(cjson.encode({kind = 'missing'})) end
local reply = redis.call('SCAN', ARGV[3], 'MATCH', ARGV[4], 'COUNT', ARGV[5])
local live, endless, latest = 0, 0, -1
for _, key in ipairs(reply[2]) do
  local expires = redis.call('PEXPIRETIME', key)
  -- -2: gone already; -1: no expiry; at or before now: expired, deleted here; else live until then.
  if expires >= 0 and expires <= now then redis.call('DEL', key)
  elseif expires == -1 then live = live + 1; endless = endless + 1
  elseif expires ~= -2 then
    live = live + 1
    if expires > latest then latest = expires end
  end
end
return out(cjson.encode({kind = 'page', cursor = reply[1], live = live, endless = endless,
  latest = num(latest), generation = entry.generation or 'none'}))
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

/** Refuses, by store's upkeep contract and with its fixed reasons (kernel's `BuildRefused`), a start the record forbids. */
function refusedStart(
	held: { readonly maintenance: boolean; readonly requires: readonly string[] },
	declared: readonly Space[],
	mayBuildUnderKey: boolean,
): void {
	if (held.maintenance && !mayBuildUnderKey) {
		throw new BuildRefused(
			"store",
			"only a tool may start while the store is under the maintenance key",
		);
	}
	const names = new Set(declared.map((space) => space.name));
	const missing = held.requires.some((name) => !names.has(name));
	if (missing && !(mayBuildUnderKey && held.maintenance)) {
		throw new BuildRefused("store", "the data requires a space this process does not declare");
	}
}

/**
 * The control record and the ledger on Redis: the reads, the upkeep, what a process does as it
 * starts (`start`), and whether the record's epoch moved from the one the process took (`moved`).
 */
export function redisUpkeepWith(parts: UpkeepParts) {
	const { run, keys, declared, taken } = parts;
	// store's checks first, before anything here reads a declaration; the ports reach later bindings only when called.
	const ports: UpkeepImplementation = {
		mark: async (name, value) => {
			await changed("mark", name, canonicalJson(value));
			return { kind: "marked" };
		},
		require: async (names) =>
			(await changed("require", JSON.stringify(names))) as Awaited<
				ReturnType<UpkeepImplementation["require"]>
			>,
		enterMaintenance: async () => {
			const epoch = Buffer.from(parts.random.bytes(16)).toString("hex");
			await changed("enter", epoch);
			taken.epoch = epoch;
			taken.keyed = true;
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
		retire: async (name, generation) =>
			(await changed("retire", name, known.has(name) ? "1" : "0", generation ?? "")) as Awaited<
				ReturnType<UpkeepImplementation["retire"]>
			>,
		sweepKept: async (name, cursor) => {
			// A cursor is a walk this process holds of this space, or a caller's error, before anything else.
			if (cursor !== undefined && walks.get(cursor)?.name !== name) {
				throw new TypeError("store: the cursor is no walk of this space that this process holds");
			}
			await ready();
			// Taken before any wait, and a page updates only its own walk: a replaced walk never comes back.
			let handle = cursor;
			if (handle === undefined) {
				const earlier = walkOf.get(name);
				if (earlier !== undefined) walks.delete(earlier);
				handle = Buffer.from(parts.random.bytes(16)).toString("hex");
				walks.set(handle, { name, scan: "0" });
				walkOf.set(name, handle);
			}
			const walk = walks.get(handle);
			// A new walk of the space may have replaced this one while the store got ready.
			if (walk === undefined) {
				throw new TypeError("store: the cursor is no walk of this space that this process holds");
			}
			const ended = () => {
				if (walks.get(handle) !== walk) return;
				walks.delete(handle);
				if (walkOf.get(name) === handle) walkOf.delete(name);
			};
			let answer: Awaited<ReturnType<typeof run>>;
			try {
				answer = await run(
					keptWalk,
					both,
					fenced([
						known.has(name) ? "1" : "0",
						name,
						walk.scan,
						keys.spaceAll(name),
						String(sweepPage),
					]),
				);
				// Removing is writing, and the space's guarantees are unknown: every page is confirmed where replication is.
				await confirm(answer);
			} catch (error) {
				ended();
				throw error;
			}
			if (answer.kind !== "page") {
				ended();
				return { kind: answer.kind } as Awaited<
					ReturnType<NonNullable<UpkeepImplementation["sweepKept"]>>
				>;
			}
			const next = String(answer.cursor);
			const done = next === "0" || walks.get(handle) !== walk;
			if (done) ended();
			else walk.scan = next;
			const latest = Number(answer.latest);
			return {
				kind: "page",
				live: answer.live as number,
				noExpiry: answer.endless as number,
				...(latest < 0 ? {} : { latestExpiry: latest }),
				...(cursor === undefined ? { generation: String(answer.generation) } : {}),
				...(done ? {} : { cursor: handle }),
				server: String(parts.serverOf(answer)),
			};
		},
		honours: (guarantees) => parts.honours(guarantees),
		sweep: async (space, cursor) => {
			await ready();
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
	const upkeep = checkedUpkeep(ports, declared);
	const both = [keys.controlKey, keys.ledgerKey];
	const fenced = (args: string[]) => [
		...args,
		keys.controlKey,
		taken.epoch,
		taken.keyed ? "1" : "0",
	];
	/** Confirms an answer on the server that computed it, where replication is declared. */
	const confirm = async <A extends object>(answer: A): Promise<A> => {
		if (parts.confirmed && (await parts.confirmed()) !== parts.serverOf(answer)) {
			throw new Unavailable("store");
		}
		return answer;
	};
	const entries = JSON.stringify(
		Object.fromEntries(declared.map((space) => [space.name, space.subjectData !== noSubjectData])),
	);
	let kept = false;
	let keeping: Promise<void> | undefined;
	/**
	 * Adds each declared space to the ledger, confirmed as a replicated write is, so a replica
	 * promoted after it holds it; kept only once it is.
	 */
	const keep = async () => {
		const generation = Buffer.from(parts.random.bytes(16)).toString("hex");
		await confirm(await run(change, both, fenced(["keep", entries, generation])));
		kept = true;
	};
	/**
	 * Before each change: until the declared spaces are on the ledger, one attempt at a time to add
	 * them, the change unavailable where it fails, so nothing changes before them.
	 */
	const ready = async () => {
		if (kept) return;
		keeping ??= keep().finally(() => {
			keeping = undefined;
		});
		await keeping;
	};
	const changed = async (op: string, ...args: string[]) => {
		await ready();
		return (await confirm(await run(change, both, fenced([op, ...args])))) as { kind: string };
	};
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
	/** A kept space's walk this process holds, by its random handle: at most one per space (`walkOf`); SCAN's cursor never leaves it. */
	const walks = new Map<string, { readonly name: string; scan: string }>();
	const walkOf = new Map<string, string>();
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
	/**
	 * As a process starts: reads the record once, refusing a start it forbids, then takes its epoch and tries to add the declared spaces to the ledger; where writes are refused, as while too few replicas are good, it boots all the same, changing nothing and unready until they are added.
	 */
	const start = async (mayBuildUnderKey = false) => {
		const held = await readAll(false);
		refusedStart(held, declared, mayBuildUnderKey);
		taken.epoch = held.epoch;
		taken.keyed = held.maintenance;
		await ready().catch(() => {});
	};
	/**
	 * What no longer holds of the process's start: the record's epoch moved from the one it took;
	 * the declared spaces not yet on the ledger, tried again; or one missing from it, or held as
	 * holding no subject's data where this process declares it may, added again.
	 */
	const recheck = async (): Promise<string[]> => {
		const held = await readAll(false);
		if (held.epoch !== taken.epoch) return ["the store's epoch moved since this process started"];
		if (taken.keyed && !held.maintenance) {
			return [
				"the maintenance key this process took its epoch under has lifted: no change is made",
			];
		}
		if (!kept) {
			const added = await ready().then(
				() => true,
				() => false,
			);
			return added ? [] : ["the declared spaces are not yet on the ledger: no change is made"];
		}
		const weakened = declared.some(
			(space) =>
				held.ledger[space.name]?.subjectDataEver !== true &&
				(!Object.hasOwn(held.ledger, space.name) || space.subjectData !== noSubjectData),
		);
		if (weakened) await keep();
		return [];
	};
	return { control, upkeep, start, recheck, ready };
}
