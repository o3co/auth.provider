import { deepFreeze } from "@mod/kernel";
import type { Source } from "@mod/request-source";
import type { z } from "zod";
import { fieldsOf, readOnly, valuesOf } from "./bodies/values.ts";
import type { HttpRequest } from "./contract.ts";
import type { section } from "./settings/section.ts";

export type HttpSettings = z.input<typeof section>;

/** The http part of a test's configuration: any free port, unless the test sets one. */
export function httpConfig(settings: Partial<HttpSettings> = {}) {
	return { http: { port: 0, ...settings } };
}

type Plain = ReadonlyMap<string, readonly string[]>;

/** A test's request: an HTTPS GET of `/` from 127.0.0.1, empty unless said; read-only as the server gives it. */
export function testRequest(
	parts: Partial<Omit<HttpRequest, "source" | "query" | "form" | "fields">> & {
		readonly query?: Plain;
		readonly form?: Plain;
		readonly fields?: Plain;
		readonly source?: Partial<Source>;
	} = {},
): HttpRequest {
	const { query, form: sentForm, fields, json: sentJson, headers, source, ...rest } = parts;
	const form = valuesOf(sentForm ?? new Map());
	const json = sentJson && deepFreeze(structuredClone(sentJson));
	const read = json ? { ...fieldsOf(json), json } : { fields: form };
	return Object.freeze({
		method: "GET",
		path: "/",
		...read,
		...rest,
		headers: readOnly(new Map(headers)),
		query: valuesOf(query ?? new Map()),
		form,
		fields: fields ? valuesOf(fields) : read.fields,
		source: Object.freeze({ address: "127.0.0.1", scheme: "https", determined: true, ...source }),
	});
}
