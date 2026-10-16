import type { IncomingMessage } from "node:http";
import { deepFreeze } from "@mod/kernel";
import type { BodyKind, HttpRequest } from "../contract.ts";
import { repeatsName } from "./json.ts";
import { fieldsOf, paramsOf, type Values, valuesOf } from "./values.ts";

const limit = 64 * 1024;

const typeOf = (message: IncomingMessage) =>
	message.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();

/** The body up to the limit; undefined past it. */
async function bytesOf(message: IncomingMessage): Promise<Buffer | undefined> {
	const chunks: Buffer[] = [];
	let size = 0;
	for await (const chunk of message) {
		size += (chunk as Buffer).length;
		if (size > limit) return undefined;
		chunks.push(chunk as Buffer);
	}
	return Buffer.concat(chunks);
}

/** Whether a request has no body: no type, and nothing sent. Reads, and so consumes, an untyped body. */
const isEmpty = async (message: IncomingMessage) =>
	typeOf(message) === undefined && (await bytesOf(message))?.length === 0;

/** A form body up to the limit; anything else, or too large, leaves the form empty. */
async function formOf(message: IncomingMessage) {
	if (typeOf(message) !== "application/x-www-form-urlencoded") return valuesOf(new Map());
	const bytes = await bytesOf(message);
	return bytes ? paramsOf(new URLSearchParams(bytes.toString("utf8"))) : valuesOf(new Map());
}

const kinds: ReadonlyMap<string | undefined, BodyKind> = new Map([
	["application/x-www-form-urlencoded", "form"],
	["application/json", "json"],
]);

/** Throws on bytes that are not UTF-8, instead of replacing them; a BOM is kept, so refused. */
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** A JSON object body, or the status that answers one that cannot be read. */
async function jsonOf(message: IncomingMessage): Promise<Record<string, unknown> | number> {
	const bytes = await bytesOf(message);
	if (!bytes) return 413;
	try {
		const text = utf8.decode(bytes);
		const value: unknown = JSON.parse(text);
		const object = typeof value === "object" && value !== null && !Array.isArray(value);
		// A name given twice is read as either value by one parser or another.
		return object && !repeatsName(text) ? deepFreeze(value as Record<string, unknown>) : 400;
	} catch {
		return 400;
	}
}

/** A body read as a form, its fields the form's; `refused` when the request is answered instead. */
const asForm = (form: Values, refused?: number) => ({
	form,
	fields: form,
	...(refused === undefined ? {} : { refused }),
});

/** A request's body as a route that takes these kinds reads it; `refused` is the status refusing it. */
export async function bodyOf(
	takes: readonly BodyKind[] | undefined,
	message: IncomingMessage,
): Promise<Pick<HttpRequest, "form" | "fields" | "json" | "mistyped"> & { refused?: number }> {
	const kind = (await isEmpty(message)) ? "none" : kinds.get(typeOf(message));
	// A route that declares no bodies reads a form when one is sent, and ignores any other.
	if (takes === undefined) return asForm(await formOf(message));
	if (kind === undefined || !takes.includes(kind)) return asForm(valuesOf(new Map()), 415);
	if (kind !== "json") return asForm(await formOf(message));
	const json = await jsonOf(message);
	if (typeof json === "number") return asForm(valuesOf(new Map()), json);
	return { form: valuesOf(new Map()), ...fieldsOf(json), json };
}
