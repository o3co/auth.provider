/** A RESP2 value, as Redis answers and clients ask. */
export type Reply =
	| { readonly kind: "simple"; readonly text: string }
	| { readonly kind: "error"; readonly text: string }
	| { readonly kind: "integer"; readonly value: number }
	| { readonly kind: "bulk"; readonly data: Buffer | null }
	| { readonly kind: "array"; readonly items: readonly Reply[] | null };

/** A request: its name, upper-cased, and its arguments as sent. */
export interface Command {
	readonly name: string;
	readonly args: readonly Buffer[];
}

/** One whole frame, read, with the bytes it came in. */
export interface Frame {
	readonly value: Reply;
	readonly bytes: Buffer;
}

const resp3 = new Set("_,#!=(%~>|".split("").map((c) => c.charCodeAt(0)));

/** The value starting at `at`, and where it ends; none while its rest has not come. */
function parse(buf: Buffer, at: number): { value: Reply; end: number } | undefined {
	const type = buf[at];
	if (type === undefined) return undefined;
	const eol = buf.indexOf("\r\n", at);
	if (eol < 0) return undefined;
	const line = buf.toString("latin1", at + 1, eol);
	const length = () => {
		if (!/^-?\d+$/.test(line)) throw new Error(`malformed RESP: ${JSON.stringify(line)}`);
		return Number(line);
	};
	switch (String.fromCharCode(type)) {
		case "+":
			return { value: { kind: "simple", text: line }, end: eol + 2 };
		case "-":
			return { value: { kind: "error", text: line }, end: eol + 2 };
		case ":":
			return { value: { kind: "integer", value: length() }, end: eol + 2 };
		case "$": {
			const n = length();
			if (n < 0) return { value: { kind: "bulk", data: null }, end: eol + 2 };
			const end = eol + 2 + n;
			if (buf.length < end + 2) return undefined;
			if (buf[end] !== 13 || buf[end + 1] !== 10) throw new Error("malformed RESP: bulk length");
			return {
				value: { kind: "bulk", data: Buffer.from(buf.subarray(eol + 2, end)) },
				end: end + 2,
			};
		}
		case "*": {
			const n = length();
			if (n < 0) return { value: { kind: "array", items: null }, end: eol + 2 };
			const items: Reply[] = [];
			let next = eol + 2;
			for (let i = 0; i < n; i++) {
				const item = parse(buf, next);
				if (!item) return undefined;
				items.push(item.value);
				next = item.end;
			}
			return { value: { kind: "array", items }, end: next };
		}
	}
	if (resp3.has(type)) throw new Error("RESP3 is not read");
	throw new Error("an inline command is not read");
}

/** Reads whole frames as bytes arrive, wherever the chunks split them; throws on what it cannot read. */
export function frames(): { push(chunk: Buffer): Frame[] } {
	let pending: Buffer = Buffer.alloc(0);
	return {
		push(chunk) {
			pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
			const read: Frame[] = [];
			let at = 0;
			for (;;) {
				const frame = parse(pending, at);
				if (!frame) break;
				read.push({ value: frame.value, bytes: Buffer.from(pending.subarray(at, frame.end)) });
				at = frame.end;
			}
			pending = pending.subarray(at);
			return read;
		},
	};
}

/** The command a request frame holds: an array of bulk strings, the first its name. */
export function commandOf(value: Reply): Command {
	const items = value.kind === "array" ? value.items : null;
	const args = items?.map((item) => (item.kind === "bulk" ? item.data : null));
	const [name, ...rest] = args ?? [];
	if (!name || !args?.every((a) => a !== null))
		throw new Error("not a command: an array of bulk strings");
	return { name: name.toString("latin1").toUpperCase(), args: rest as Buffer[] };
}
