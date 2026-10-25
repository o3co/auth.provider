import type { Command, Match, Reply, Role } from "../relay/relay.ts";

/** A store operation, as the Redis adapter calls it. */
export type Operation = "putIfAbsent" | "replaceIf" | "removeIf" | "take" | "count" | "batch";

export interface StoreKey {
	readonly space: string;
	readonly partition: string;
	readonly name: string;
}

interface Call {
	readonly operation: Operation | "read";
	readonly keys: readonly string[];
	readonly argv: readonly string[];
}

const writtenKinds = new Set(["written", "removed", "taken", "committed", "counted"]);
// A key is `<prefix>:{<space>:<partition>}:<v|c>:<name>`, each part URI-encoded but the prefix.
const keyShape = /^(.*):\{([^:{}]*):([^:{}]*)\}:(v|c):(.*)$/;

const decode = (key: string): (StoreKey & { readonly prefix: string }) | undefined => {
	const m = keyShape.exec(key);
	if (!m) return undefined;
	const [, prefix = "", space = "", partition = "", , name = ""] = m;
	const d = decodeURIComponent;
	return { prefix, space: d(space), partition: d(partition), name: d(name) };
};

const parsed = (text: string | undefined): unknown => {
	try {
		return text === undefined ? undefined : JSON.parse(text);
	} catch {
		return undefined;
	}
};

const specOf = (text: string | undefined) => {
	const spec = parsed(text) as { writes?: { i: number; put?: string }[] } | undefined;
	return Array.isArray(spec?.writes) ? spec.writes : undefined;
};

/** The store call an `EVAL` makes, told by the shape of its keys and arguments. */
function callOf(command: Command): Call | undefined {
	if (command.name !== "EVAL") return undefined;
	const [, numkeys, ...rest] = command.args.map((a) => a.toString());
	const n = Number(numkeys);
	const keys = rest.slice(0, n);
	const argv = rest.slice(n);
	const [first, second] = keys;
	const marks = keys.at(-1)?.includes(":#mark:") ?? false;
	if (n === 1 && first?.includes(":v:") && argv.length === 0)
		return { operation: "read", keys, argv };
	if (n === 3 && second?.endsWith(":#version") && marks) {
		if (argv[0] === "putIfAbsent" || argv[0] === "replaceIf")
			return { operation: argv[0], keys, argv };
	}
	if (n === 2 && marks && first?.includes(":c:")) return { operation: "count", keys, argv };
	if (n === 2 && marks && first?.includes(":v:")) {
		if (argv[0] === "version" || argv[0] === "value") return { operation: "removeIf", keys, argv };
		if (argv.length === 3) return { operation: "take", keys, argv };
	}
	if (n >= 3 && marks && specOf(argv[0])) return { operation: "batch", keys, argv };
	return undefined;
}

/** The keys a call reaches, by space, partition and name. */
export function keysOf(command: Command): StoreKey[] {
	return (callOf(command)?.keys ?? []).flatMap((key) => {
		const k = decode(key);
		return k ? [{ space: k.space, partition: k.partition, name: k.name }] : [];
	});
}

/** What a write puts, by key: a value read as JSON. */
export function writtenValues(command: Command): { key: StoreKey; value: unknown }[] {
	const call = callOf(command);
	const keyAt = (at: number) => {
		const k = decode(call?.keys[at] ?? "");
		return k && { space: k.space, partition: k.partition, name: k.name };
	};
	if (call?.operation === "putIfAbsent" || call?.operation === "replaceIf") {
		const key = keyAt(0);
		return key ? [{ key, value: parsed(call.argv[1]) }] : [];
	}
	if (call?.operation !== "batch") return [];
	return (specOf(call.argv[0]) ?? []).flatMap((w) => {
		const key = keyAt(w.i - 1);
		return key && w.put !== undefined ? [{ key, value: parsed(w.put) }] : [];
	});
}

/** The answer of a store script: the server's run id on its first line, then its JSON. */
const answerOf = (reply: Reply) => {
	if (reply.kind !== "bulk" || reply.data === null) return undefined;
	const text = reply.data.toString();
	const split = text.indexOf("\n");
	return split < 0
		? undefined
		: { runId: text.slice(0, split), body: parsed(text.slice(split + 1)) };
};

export const runIdOf = (reply: Reply) => answerOf(reply)?.runId;

const wrote = (reply: Reply) => {
	const kind = (answerOf(reply)?.body as { kind?: unknown } | undefined)?.kind;
	return typeof kind === "string" && writtenKinds.has(kind);
};

export interface StoreWrite {
	/** The deployment's `redis.prefix`. */
	readonly prefix: string;
	readonly space: string;
	/** By default, every write. */
	readonly operations?: readonly Operation[];
	readonly name?: string;
	readonly partition?: string;
	/** What the write puts to the key, read as JSON. */
	readonly value?: (value: unknown) => boolean;
}

/** A write to a space's key, succeeded where its answer says it wrote. */
export function storeWrite(w: StoreWrite): Match {
	const ours = (k: StoreKey & { prefix: string }) =>
		k.prefix === w.prefix &&
		k.space === w.space &&
		(w.name === undefined || k.name === w.name) &&
		(w.partition === undefined || k.partition === w.partition);
	return {
		request: (command) => {
			const call = callOf(command);
			if (!call || call.operation === "read") return false;
			if (w.operations && !w.operations.includes(call.operation)) return false;
			if (!w.value)
				return call.keys.some((key) => ((k) => k !== undefined && ours(k))(decode(key)));
			const { value } = w;
			return writtenValues(command).some(
				({ key, value: put }) => ours({ ...key, prefix: w.prefix }) && value(put),
			);
		},
		succeeded: wrote,
	};
}

/** A read of a space's key, succeeded unless Redis answered an error. */
export function storeRead(r: { prefix: string; space: string; name?: string }): Match {
	return {
		request: (command) => {
			const call = callOf(command);
			const k = call?.operation === "read" ? decode(call.keys[0] ?? "") : undefined;
			return (
				!!k &&
				k.prefix === r.prefix &&
				k.space === r.space &&
				(r.name === undefined || k.name === r.name)
			);
		},
		succeeded: (reply) => answerOf(reply) !== undefined,
	};
}

/** A call's mark: its mark key, where it carries one. */
const markOf = (command: Command) => {
	const call = callOf(command);
	const key = call?.keys.at(-1);
	return call?.argv.at(-1) === "1" && key && !key.endsWith(":#mark:") ? key : undefined;
};

/** Whether `later` is a resend of `first`: the same mark. */
export const sameMark = (first: Command, later: Command) => {
	const m = markOf(first);
	return m !== undefined && m === markOf(later);
};

/** A connection's role, from what only that one sends: the confirming connection's round, or a script. */
export function roleOf(command: Command): Role | undefined {
	if (command.name === "WAIT") return "confirming";
	if (command.name === "SET" && command.args[0]?.toString().endsWith(":#confirm"))
		return "confirming";
	if (command.name === "EVAL") return "operations";
	return undefined;
}

/** A confirmation's `WAIT`, succeeded where as many replicas as the scene has acknowledged. */
export function confirmation(of: { replicas: number }): Match {
	return {
		request: (command) => command.name === "WAIT" && Number(command.args[0]?.toString()) >= 1,
		succeeded: (reply) => reply.kind === "integer" && reply.value >= of.replicas,
	};
}

export const isNoReplicas = (reply: Reply) =>
	reply.kind === "error" && /\bNOREPLICAS\b/.test(reply.text);
export const isOutOfMemory = (reply: Reply) => reply.kind === "error" && /\bOOM\b/.test(reply.text);
