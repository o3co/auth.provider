import type { IncomingMessage } from "node:http";
import { deepFreeze } from "@mod/kernel";
import type { BodyKind, HttpRequest } from "../contract.ts";
import { repeatsName } from "./json.ts";
import { fieldsOf, paramsOf, type Values, valuesOf } from "./values.ts";

const limit = 64 * 1024;

/** The statuses refusing a body: one that cannot be read, one past the limit, one of a type the route does not take. */
const badRequest = 400;
const tooLarge = 413;
const unsupportedType = 415;

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

/** Throws on bytes that are not UTF-8, instead of replacing them; a BOM is kept (so a JSON body with one is refused). */
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** A form body up to the limit; anything else, or too large, leaves the form empty. `400` when it is not UTF-8. */
async function formOf(message: IncomingMessage): Promise<Values | number> {
	if (typeOf(message) !== "application/x-www-form-urlencoded") return valuesOf(new Map());
	const bytes = await bytesOf(message);
	if (!bytes) return valuesOf(new Map());
	try {
		return paramsOf(utf8.decode(bytes)) ?? badRequest;
	} catch {
		return badRequest;
	}
}

const kinds: ReadonlyMap<string | undefined, BodyKind> = new Map([
	["application/x-www-form-urlencoded", "form"],
	["application/json", "json"],
]);

/** A JSON object body, or the status that answers one that cannot be read. */
async function jsonOf(message: IncomingMessage): Promise<Record<string, unknown> | number> {
	const bytes = await bytesOf(message);
	if (!bytes) return tooLarge;
	try {
		const text = utf8.decode(bytes);
		const value: unknown = JSON.parse(text);
		const object = typeof value === "object" && value !== null && !Array.isArray(value);
		// A name given twice is read as either value by one parser or another.
		return object && !repeatsName(text) ? deepFreeze(value as Record<string, unknown>) : badRequest;
	} catch {
		return badRequest;
	}
}

/** A body read as a form, its fields the form's; `refused` when the request is answered instead. */
const asForm = (form: Values, refused?: number) => ({
	form,
	fields: form,
	...(refused === undefined ? {} : { refused }),
});

/** A form body read as a form, or refused as one that is not UTF-8. */
const readForm = async (message: IncomingMessage) => {
	const form = await formOf(message);
	return typeof form === "number" ? asForm(valuesOf(new Map()), form) : asForm(form);
};

/** A request's body as a route that takes these kinds reads it; `refused` is the status refusing it. */
export async function bodyOf(
	takes: readonly BodyKind[] | undefined,
	message: IncomingMessage,
): Promise<Pick<HttpRequest, "form" | "fields" | "json" | "mistyped"> & { refused?: number }> {
	const kind = (await isEmpty(message)) ? "none" : kinds.get(typeOf(message));
	// A route that declares no bodies reads a form when one is sent, and ignores any other.
	if (takes === undefined) return readForm(message);
	if (kind === undefined || !takes.includes(kind))
		return asForm(valuesOf(new Map()), unsupportedType);
	if (kind !== "json") return readForm(message);
	const json = await jsonOf(message);
	if (typeof json === "number") return asForm(valuesOf(new Map()), json);
	return { form: valuesOf(new Map()), ...fieldsOf(json), json };
}
