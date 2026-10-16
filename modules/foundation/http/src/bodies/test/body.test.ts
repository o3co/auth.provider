import type { IncomingMessage } from "node:http";
import { Readable } from "node:stream";
import { expect, it } from "vitest";
import type { BodyKind } from "../../contract.ts";
import { bodyOf } from "../body.ts";

/** A request sending these bytes under this type. */
const sending = (type: string | undefined, body: string | Buffer) =>
	Object.assign(Readable.from([Buffer.from(body)]), {
		headers: type === undefined ? {} : { "content-type": type },
	}) as unknown as IncomingMessage;

const read = (
	takes: readonly BodyKind[] | undefined,
	type: string | undefined,
	body: string | Buffer,
) => bodyOf(takes, sending(type, body));

it("reads a body of exactly 64 KiB, and refuses one byte more", async () => {
	const json = (size: number) => `{"a":"${"x".repeat(size - 8)}"}`;
	expect(json(65_536)).toHaveLength(65_536);
	expect((await read(["json"], "application/json", json(65_536))).refused).toBeUndefined();
	expect((await read(["json"], "application/json", json(65_537))).refused).toBe(413);
});

it("reads the type in any case, without its parameters", async () => {
	const found = await read(["json"], "Application/JSON; charset=utf-8", '{"a":"1"}');
	expect(found.json).toEqual({ a: "1" });
});

it("reads a form past the limit as empty", async () => {
	const form = `a=${"x".repeat(70 * 1024)}`;
	const found = await read(undefined, "application/x-www-form-urlencoded", form);
	expect([found.form.size, found.refused]).toEqual([0, undefined]);
});

it("refuses a JSON body that is not well-formed UTF-8", async () => {
	const broken = Buffer.concat([Buffer.from('{"a":"'), Buffer.from([0xff]), Buffer.from('"}')]);
	expect((await read(["json"], "application/json", broken)).refused).toBe(400);
	const marked = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('{"a":"1"}')]);
	expect((await read(["json"], "application/json", marked)).refused).toBe(400);
});
