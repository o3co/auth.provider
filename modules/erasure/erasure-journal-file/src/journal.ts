import { createHash } from "node:crypto";
import { hostname } from "node:os";
import type { ErasureJournal, JournalEntry, JournalHeader, Unusable } from "@mod/erasure-journal";
import { type Clock, type Random, Unavailable } from "@mod/kernel";
import type { JournalFiles } from "./files.ts";

type Header = { readonly type: "header"; readonly format: 1; readonly id: string };
type Begun = {
	readonly type: "begun";
	readonly n: number;
	readonly subject: string;
	readonly requestedBy: string;
	readonly at: number;
};
type Finished = { readonly type: "finished"; readonly n: number; readonly subject: string };
type Entry = Begun | Finished;

const unusable = (reason: Unusable["reason"]): Unusable => ({ kind: "unusable", reason });
const digest = (body: Buffer) => createHash("sha256").update(body).digest("hex");

/** One record: its body's length in bytes, the body (JSON), its SHA-256 in hex, then a line feed. */
export function framed(record: Header | Entry): Buffer {
	const body = Buffer.from(JSON.stringify(record));
	return Buffer.concat([Buffer.from(`${body.length} `), body, Buffer.from(` ${digest(body)}\n`)]);
}

/**
 * The records a file holds, in order: torn where the last one does not match its length or
 * checksum, corrupt where an earlier one does not, or where they do not read as a header then
 * records numbered from 1.
 */
export function readRecords(bytes: Buffer): { header: Header; entries: Entry[] } | Unusable {
	const bodies: Buffer[] = [];
	let at = 0;
	while (at < bytes.length) {
		const space = bytes.indexOf(0x20, at);
		const length = space > at ? Number(bytes.subarray(at, space).toString()) : Number.NaN;
		const end = space + 1 + length;
		const whole =
			Number.isSafeInteger(length) &&
			length >= 0 &&
			end + 66 <= bytes.length &&
			bytes[end] === 0x20 &&
			bytes[end + 65] === 0x0a;
		const body = whole ? bytes.subarray(space + 1, end) : undefined;
		if (!body || bytes.subarray(end + 1, end + 65).toString() !== digest(body)) {
			// A record that does not match is torn where nothing follows it, and corrupt where something does.
			const next = bytes.indexOf(0x0a, at);
			return unusable(next < 0 || next === bytes.length - 1 ? "torn" : "corrupt");
		}
		bodies.push(body);
		at = end + 66;
	}
	try {
		const [first, ...rest] = bodies.map((body) => JSON.parse(body.toString()));
		if (first?.type !== "header" || first.format !== 1 || typeof first.id !== "string") {
			return unusable(first === undefined ? "torn" : "corrupt");
		}
		const entries = rest as Entry[];
		const numbered = entries.every(
			(e, i) => e.n === i + 1 && (e.type === "begun" || e.type === "finished"),
		);
		return numbered ? { header: first as Header, entries } : unusable("corrupt");
	} catch {
		return unusable("corrupt");
	}
}

/** The journal in the file at `path`, kept by `files`. */
export function journalFileWith(parts: {
	readonly path: string;
	readonly files: JournalFiles;
	readonly clock: Clock;
	readonly random: Random;
}): ErasureJournal {
	const { path, files } = parts;
	/** What the file holds, missing where there is none; any other failure of the medium is unavailable. */
	const records = async () => {
		let bytes: Buffer;
		try {
			bytes = await files.read(path);
		} catch (error) {
			if ((error as { code?: unknown }).code === "ENOENT") return unusable("missing");
			throw new Unavailable("erasure-journal");
		}
		return readRecords(bytes);
	};
	/** Under the lock: what the file holds, then one record appended, numbered next. */
	const appended = async (record: (n: number) => Entry) => {
		let release: () => Promise<void>;
		try {
			const holder = JSON.stringify({ pid: process.pid, host: hostname(), at: parts.clock.now() });
			release = await files.lock(path, holder);
		} catch (error) {
			const { code, holder } = error as { code?: unknown; holder?: unknown };
			// Named, so an operator finds a lock a crash left behind, and whose it was.
			if (code === "EEXIST") {
				throw new Unavailable(`erasure-journal (its lock ${path}.lock is held: ${String(holder)})`);
			}
			throw new Unavailable("erasure-journal");
		}
		try {
			const held = await records();
			if ("kind" in held) return held;
			const n = held.entries.length + 1;
			try {
				await files.append(path, framed(record(n)));
			} catch {
				throw new Unavailable("erasure-journal");
			}
			return { number: n };
		} finally {
			await release().catch(() => {});
		}
	};
	return {
		create: async () => {
			const id = Buffer.from(parts.random.bytes(16)).toString("hex");
			try {
				await files.create(path, framed({ type: "header", format: 1, id }));
			} catch (error) {
				if ((error as { code?: unknown }).code === "EEXIST") return { kind: "exists" };
				throw new Unavailable("erasure-journal");
			}
			return { kind: "created", id };
		},
		header: async (): Promise<JournalHeader | Unusable> => {
			const held = await records();
			return "kind" in held ? held : { id: held.header.id, number: held.entries.length };
		},
		begun: (subject, requestedBy) =>
			appended((n) => ({ type: "begun", n, subject, requestedBy, at: parts.clock.now() })),
		finished: (subject) => appended((n) => ({ type: "finished", n, subject })),
		list: async (): Promise<readonly JournalEntry[] | Unusable> => {
			const held = await records();
			if ("kind" in held) return held;
			const bySubject = new Map<string, JournalEntry>();
			for (const e of held.entries) {
				const before = bySubject.get(e.subject);
				if (e.type === "begun") {
					// Begun again keeps the place where it first began; the rest is the later run's.
					bySubject.set(e.subject, {
						subject: e.subject,
						requestedBy: e.requestedBy,
						begunAt: e.at,
						finished: false,
						number: e.n,
					});
				} else if (before) {
					bySubject.set(e.subject, { ...before, finished: true, number: e.n });
				}
			}
			return [...bySubject.values()];
		},
	};
}
