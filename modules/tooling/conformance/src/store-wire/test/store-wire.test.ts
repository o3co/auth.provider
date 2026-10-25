import { describe, expect, it } from "vitest";
import type { Command, Reply } from "../../relay/relay.ts";
import {
	confirmation,
	isNoReplicas,
	isOutOfMemory,
	keysOf,
	roleOf,
	runIdOf,
	sameMark,
	storeRead,
	storeWrite,
	writtenValues,
} from "../store-wire.ts";

// Copies of the Redis adapter's wire as it is now (redis-store.ts): its keys, its script calls and
// its answers. Each scene's control checks the real one.
const prefix = "app";
const enc = encodeURIComponent;
const slot = (space: string, partition = "") => `${prefix}:{${enc(space)}:${enc(partition)}}`;
const value = (space: string, name: string, partition = "") =>
	`${slot(space, partition)}:v:${enc(name)}`;
const version = (space: string, partition = "") => `${slot(space, partition)}:#version`;
const mark = (space: string, m = "", partition = "") => `${slot(space, partition)}:#mark:${enc(m)}`;
const evalOf = (keys: string[], argv: string[]): Command => ({
	name: "EVAL",
	args: ["-- script", String(keys.length), ...keys, ...argv].map((s) => Buffer.from(s)),
});
const command = (name: string, ...args: string[]): Command => ({
	name,
	args: args.map((a) => Buffer.from(a)),
});
const write = (mode: string, space: string, name: string, put: unknown, m = "", partition = "") =>
	evalOf(
		[value(space, name, partition), version(space, partition), mark(space, m, partition)],
		[mode, JSON.stringify(put), "", "never", "", "", "digest", m ? "1" : "0"],
	);
const removeIf = (space: string, name: string) =>
	evalOf([value(space, name), mark(space)], ["version", "3", "", "digest", "0"]);
const take = (space: string, name: string) =>
	evalOf([value(space, name), mark(space)], ["", "digest", "0"]);
const count = (space: string, name: string) =>
	evalOf([`${slot(space)}:c:${enc(name)}`, mark(space)], ["60000", "5", "", "digest", "0"]);
const read = (space: string, name: string) => evalOf([value(space, name)], []);
const batch = (space: string, names: string[], puts: unknown[]) =>
	evalOf(
		[...names.map((n) => value(space, n)), version(space), mark(space)],
		[
			JSON.stringify({
				conditions: [],
				writes: puts.map((put, i) => ({
					i: i + 1,
					put: JSON.stringify(put),
					kind: "never",
					arg: "",
				})),
			}),
			"",
			"digest",
			"0",
		],
	);
/** A batch as the adapter sends it: every key it reaches, its conditions and its writes by index. */
const batchOf = (
	keyNames: string[],
	conditions: { i: number; version: string }[],
	writes: ({ i: number; put: unknown } | { i: number; remove: true })[],
	p = prefix,
) =>
	evalOf(
		[...keyNames.map((n) => `${p}:{s:}:v:${n}`), `${p}:{s:}:#version`, `${p}:{s:}:#mark:`],
		[
			JSON.stringify({
				conditions,
				writes: writes.map((w) =>
					"put" in w ? { i: w.i, put: JSON.stringify(w.put), kind: "never", arg: "" } : w,
				),
			}),
			"",
			"digest",
			"0",
		],
	);
const answer = (kind: string): Reply => ({
	kind: "bulk",
	data: Buffer.from(`run1\n${JSON.stringify({ kind })}`),
});

describe("a store write", () => {
	const closings = "session-lifecycle.closings";

	it("matches a write to the space, by operation, name and what it puts", () => {
		const add = storeWrite({
			prefix,
			space: closings,
			operations: ["putIfAbsent", "replaceIf"],
			name: "jobs",
			value: (v) => Array.isArray(v) && v.includes("h1"),
		});
		expect(add.request(write("replaceIf", closings, "jobs", ["h1"], "", "jobs-0"))).toBe(true);
		expect(add.request(write("putIfAbsent", closings, "jobs", ["h1"]))).toBe(true);
		expect(add.request(write("replaceIf", closings, "jobs", ["h2"]))).toBe(false);
		expect(add.request(write("replaceIf", "other", "jobs", ["h1"]))).toBe(false);
		expect(add.request(write("replaceIf", closings, "else", ["h1"]))).toBe(false);
		expect(add.request(removeIf(closings, "jobs"))).toBe(false);
		expect(add.request(read(closings, "jobs"))).toBe(false);
		expect(add.request(command("GET", value(closings, "jobs")))).toBe(false);
	});

	it("tells each operation by the shape of its call", () => {
		const of = (operations: Parameters<typeof storeWrite>[0]["operations"]) =>
			storeWrite({ prefix, space: "s", ...(operations ? { operations } : {}) });
		expect(of(["removeIf"]).request(removeIf("s", "a"))).toBe(true);
		expect(of(["take"]).request(take("s", "a"))).toBe(true);
		expect(of(["take"]).request(removeIf("s", "a"))).toBe(false);
		expect(of(["count"]).request(count("s", "a"))).toBe(true);
		expect(of(["batch"]).request(batch("s", ["a", "b"], [1, 2]))).toBe(true);
		expect(of(undefined).request(read("s", "a"))).toBe(false);
	});

	it("matches a batch where one of its writes is to the space and puts what is asked", () => {
		const match = storeWrite({ prefix, space: "s", name: "b", value: (v) => v === 2 });
		expect(match.request(batch("s", ["a", "b"], [1, 2]))).toBe(true);
		expect(match.request(batch("s", ["a", "b"], [2, 1]))).toBe(false);
	});

	it("does not match a batch whose key in the space only stands in a condition", () => {
		const a = storeWrite({ prefix, space: "s", name: "a" });
		const checksAWritesB = batchOf(["a", "b"], [{ i: 1, version: "3" }], [{ i: 2, put: 1 }]);
		expect(a.request(checksAWritesB)).toBe(false);
		expect(storeWrite({ prefix, space: "s", name: "b" }).request(checksAWritesB)).toBe(true);
		expect(a.request(batchOf(["a"], [], [{ i: 1, remove: true }]))).toBe(true);
		expect(keysOf(checksAWritesB).map((k) => k.name)).toEqual(["a", "b"]);
	});

	it("matches only the deployment's prefix, a value asked for or not", () => {
		const put = (p: string) => batchOf(["a"], [], [{ i: 1, put: 1 }], p);
		const write = (p: string) =>
			evalOf(
				[`${p}:{s:}:v:a`, `${p}:{s:}:#version`, `${p}:{s:}:#mark:`],
				["putIfAbsent", "1", "", "never", "", "", "d", "0"],
			);
		for (const match of [
			storeWrite({ prefix, space: "s", name: "a", value: (v) => v === 1 }),
			storeWrite({ prefix, space: "s", name: "a" }),
		]) {
			expect(match.request(put("other"))).toBe(false);
			expect(match.request(write("other"))).toBe(false);
			expect(match.request(put(prefix))).toBe(true);
			expect(match.request(write(prefix))).toBe(true);
		}
	});

	it("succeeds only where the answer's kind wrote", () => {
		const match = storeWrite({ prefix, space: "s" });
		for (const kind of ["written", "removed", "taken", "committed", "counted"]) {
			expect(match.succeeded(answer(kind))).toBe(true);
		}
		for (const kind of ["exists", "missing", "conflict", "refused", "late"]) {
			expect(match.succeeded(answer(kind))).toBe(false);
		}
		expect(match.succeeded({ kind: "error", text: "NOREPLICAS Not enough good replicas" })).toBe(
			false,
		);
		expect(match.succeeded({ kind: "simple", text: "OK" })).toBe(false);
	});
});

describe("a store read", () => {
	it("matches the read of the space's key, and succeeds unless an error", () => {
		const match = storeRead({ prefix, space: "s", name: "a" });
		expect(match.request(read("s", "a"))).toBe(true);
		expect(match.request(read("s", "b"))).toBe(false);
		expect(match.request(take("s", "a"))).toBe(false);
		expect(match.succeeded({ kind: "bulk", data: Buffer.from('run1\n{"entries":[]}') })).toBe(true);
		expect(match.succeeded({ kind: "error", text: "ERR" })).toBe(false);
	});
});

describe("what a call and its answer tell", () => {
	it("names the keys a call reaches, by space, partition and name", () => {
		expect(
			keysOf(write("replaceIf", "session-lifecycle.closings", "jobs", [], "", "jobs-3")),
		).toEqual([{ space: "session-lifecycle.closings", partition: "jobs-3", name: "jobs" }]);
		expect(keysOf(command("SET", `${prefix}:#confirm`, "1"))).toEqual([]);
	});

	it("reads what a write puts, by key", () => {
		expect(writtenValues(write("replaceIf", "s", "jobs", ["h1"]))).toEqual([
			{ key: { space: "s", partition: "", name: "jobs" }, value: ["h1"] },
		]);
		expect(writtenValues(batch("s", ["a", "b"], [1, { x: 2 }])).map((w) => w.value)).toEqual([
			1,
			{ x: 2 },
		]);
		expect(writtenValues(removeIf("s", "a"))).toEqual([]);
	});

	it("tells a resend by its mark", () => {
		const first = write("replaceIf", "s", "a", 1, "m1");
		expect(sameMark(first, write("replaceIf", "s", "a", 1, "m1"))).toBe(true);
		expect(sameMark(first, write("replaceIf", "s", "a", 1, "m2"))).toBe(false);
		expect(sameMark(write("replaceIf", "s", "a", 1), write("replaceIf", "s", "a", 1))).toBe(false);
	});

	it("reads the server an answer came from", () => {
		expect(runIdOf(answer("written"))).toBe("run1");
		expect(runIdOf({ kind: "simple", text: "OK" })).toBeUndefined();
	});

	it("names a connection's role by what only that one sends", () => {
		expect(roleOf(command("WAIT", "2", "1000"))).toBe("confirming");
		expect(roleOf(command("SET", `${prefix}:#confirm`, "1", "PX", "60000"))).toBe("confirming");
		expect(roleOf(read("s", "a"))).toBe("operations");
		expect(roleOf(command("ROLE"))).toBeUndefined();
		expect(roleOf(command("INFO", "server"))).toBeUndefined();
	});

	it("matches a confirmation's WAIT, succeeded where the replicas the scene has acknowledged", () => {
		const match = confirmation({ replicas: 2 });
		const wait = command("WAIT", "2", "1000");
		expect(match.request(wait)).toBe(true);
		expect(match.request(command("WAIT", "0", "1"))).toBe(false);
		expect(match.succeeded({ kind: "integer", value: 2 })).toBe(true);
		expect(match.succeeded({ kind: "integer", value: 1 })).toBe(false);
	});

	it("tells the refusals of a write: no good replicas, out of memory", () => {
		expect(
			isNoReplicas({ kind: "error", text: "NOREPLICAS Not enough good replicas to write." }),
		).toBe(true);
		expect(
			isOutOfMemory({
				kind: "error",
				text: "OOM command not allowed when used memory > 'maxmemory'.",
			}),
		).toBe(true);
		expect(isNoReplicas({ kind: "error", text: "ERR other" })).toBe(false);
		expect(isOutOfMemory(answer("written"))).toBe(false);
	});
});
