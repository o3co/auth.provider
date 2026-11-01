import { describe, expect, it } from "vitest";
import { commandOf, frames } from "../resp.ts";

const bytes = (text: string) => Buffer.from(text, "latin1");

describe("reading RESP2 frames", () => {
	it("reads each kind, a nested array and the nulls", () => {
		const read = frames().push(
			bytes("+OK\r\n-ERR no\r\n:42\r\n$3\r\nabc\r\n$-1\r\n*-1\r\n*2\r\n*1\r\n:1\r\n$0\r\n\r\n"),
		);
		expect(read.map((f) => f.value)).toEqual([
			{ kind: "simple", text: "OK" },
			{ kind: "error", text: "ERR no" },
			{ kind: "integer", value: 42 },
			{ kind: "bulk", data: bytes("abc") },
			{ kind: "bulk", data: null },
			{ kind: "array", items: null },
			{
				kind: "array",
				items: [
					{ kind: "array", items: [{ kind: "integer", value: 1 }] },
					{ kind: "bulk", data: bytes("") },
				],
			},
		]);
	});

	it("keeps each frame's own bytes, so it is passed on as it came", () => {
		const text = "$4\r\na\r\nb\r\n:7\r\n";
		const read = frames().push(bytes(text));
		expect(read.map((f) => f.bytes.toString("latin1"))).toEqual(["$4\r\na\r\nb\r\n", ":7\r\n"]);
	});

	it("holds a frame split across chunks until its rest comes, at any byte", () => {
		const text = "*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\nv1\r\n+PONG\r\n";
		const reader = frames();
		const read = [...bytes(text)].flatMap((b) => reader.push(Buffer.from([b])));
		expect(read.map((f) => f.bytes.toString("latin1"))).toEqual([
			"*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$2\r\nv1\r\n",
			"+PONG\r\n",
		]);
	});

	it("refuses RESP3, inline commands and broken frames", () => {
		expect(() => frames().push(bytes("%1\r\n+a\r\n+b\r\n"))).toThrow(/RESP3/);
		expect(() => frames().push(bytes("_\r\n"))).toThrow(/RESP3/);
		expect(() => frames().push(bytes("PING\r\n"))).toThrow(/inline/);
		expect(() => frames().push(bytes("$x\r\n"))).toThrow(/malformed/);
		expect(() => frames().push(bytes("$1\r\nab\r\n"))).toThrow(/malformed/);
	});
});

describe("a command from a frame", () => {
	it("is its name, upper-cased, and its arguments as bytes", () => {
		const [frame] = frames().push(bytes("*3\r\n$4\r\neval\r\n$1\r\n1\r\n$1\r\nk\r\n"));
		expect(frame && commandOf(frame.value)).toEqual({
			name: "EVAL",
			args: [bytes("1"), bytes("k")],
		});
	});

	it("is refused unless an array of bulk strings", () => {
		const [frame] = frames().push(bytes("*1\r\n:1\r\n"));
		expect(() => frame && commandOf(frame.value)).toThrow(/not a command/);
	});
});
