import type { HttpRequest } from "@mod/http";
import { deepFreeze } from "@mod/kernel";
import type { StandardSchemaV1 } from "@standard-schema/spec";
import { z } from "zod";
import type {
	Authentication,
	AuthMethod,
	Client,
	ClientRecord,
	ClientSource,
	Clients,
	Section,
} from "./contract.ts";
import { none } from "./methods.ts";

type Refused = Extract<Authentication, { kind: "refused" }>;

export interface SectionIssue {
	readonly path: string;
	readonly message: string;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: finding control characters is the point.
const unnameableCharacter = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ufeff]/;

/** Whether an id can name a client: 1 to 256 UTF-16 code units, no lone surrogate, and no C0, DEL, C1, U+2028, U+2029 or BOM. */
const nameable = (id: string) =>
	id.length > 0 && id.length <= 256 && id.isWellFormed() && !unnameableCharacter.test(id);

/** A client record as the operator registers it, and as a source's answer is held to. */
export const clientRecord = z.strictObject({
	id: z
		.string()
		.refine(
			nameable,
			"a client id that is empty, over 256 code units or with a character no id may hold",
		),
	kind: z.enum(["public", "confidential"]),
	method: z.string().min(1),
	sections: z.record(z.string(), z.unknown()).default({}),
});

const pathOf = (issue: StandardSchemaV1.Issue) =>
	(issue.path ?? []).map((s) => String(typeof s === "object" ? s.key : s)).join(".");

/** Checks every section of a record; the whole record is refused if any section is wrong. */
export async function readRecord(
	record: ClientRecord,
	known: ReadonlyMap<string, Section<unknown>>,
	origin: "registered" | "source",
): Promise<{ client: Client } | { issues: SectionIssue[] }> {
	const issues: SectionIssue[] = [];
	const values = new Map<string, unknown>();
	for (const name of Object.keys(record.sections)) {
		if (!known.has(name)) issues.push({ path: name, message: "unknown section" });
	}
	for (const [name, section] of known) {
		const result = await section.schema["~standard"].validate(record.sections[name] ?? {});
		if (result.issues) {
			for (const issue of result.issues) {
				const path = pathOf(issue);
				issues.push({ path: path ? `${name}.${path}` : name, message: issue.message });
			}
		} else values.set(name, deepFreeze(result.value));
	}
	if (issues.length > 0) return { issues };
	const client: Client = Object.freeze({
		id: record.id,
		kind: record.kind,
		method: record.method,
		registered: origin === "registered",
		section: <T>(section: Section<T>) => values.get(section.name) as T,
	});
	return { client };
}

export function registry(
	registered: ReadonlyMap<string, Client>,
	sources: readonly ClientSource[],
	methods: readonly AuthMethod[],
	known: ReadonlyMap<string, Section<unknown>>,
): Clients {
	const held = async (record: unknown, id: string): Promise<Client | "invalid"> => {
		const parsed = clientRecord.safeParse(record);
		if (!parsed.success) return "invalid";
		const { data } = parsed;
		if (data.id !== id) return "invalid";
		if (!methods.some((m) => m.name === data.method)) return "invalid";
		const read = await readRecord(data, known, "source");
		return "client" in read ? read.client : "invalid";
	};
	/** A source's record held to the registered rule, a usable method and the id asked; one that throws while read is invalid. */
	const sourced = (record: unknown, id: string) => held(record, id).catch(() => "invalid" as const);
	/** The client by id: registered first, then the first source that names it; "invalid" if its record fails. */
	const lookup = async (id: string): Promise<Client | undefined | "invalid"> => {
		// An id no client can have is looked up nowhere, so no source can fail on it.
		if (!nameable(id)) return undefined;
		const local = registered.get(id);
		if (local) return local;
		for (const source of sources) {
			const record = await source.find(id);
			if (!record) continue;
			return sourced(record, id);
		}
		return undefined;
	};
	return {
		methods: () => methods.map((m) => m.name),
		signingAlgorithms: () => [...new Set(methods.flatMap((m) => m.signingAlgorithms ?? []))],
		find: async (id) => {
			const found = await lookup(id);
			return found === "invalid" ? undefined : found;
		},
		authenticate: async (request: HttpRequest): Promise<Authentication> => {
			const claim = (method: AuthMethod) => {
				const id = method.claimed(request);
				return id === undefined ? [] : [{ method, id }];
			};
			// `none` is what a request is when no other method claims it, and only then is it read.
			const others = methods.filter((m) => m.name !== none.name);
			const claimed = others.flatMap(claim);
			const tried = claimed.length > 0 ? claimed : claim(none);
			const read = claimed.length > 0 ? others : methods;
			const [only, ...more] = tried;
			const every = methods.flatMap((m) => (m.challenge ? [m.challenge] : []));
			if (more.length > 0) return { kind: "refused", reason: "multiple_methods", challenges: [] };
			if (read.some((method) => method.malformed?.(request))) {
				return { kind: "refused", reason: "malformed_credentials", challenges: [] };
			}
			if (!only) return { kind: "refused", reason: "no_credentials", challenges: every };
			const challenges = only.method.challenge ? [only.method.challenge] : [];
			const refused = (reason: Refused["reason"]) =>
				({ kind: "refused", reason, challenges }) as const;
			const found = await lookup(only.id);
			if (found === undefined) return refused("unknown_client");
			if (found === "invalid") return refused("invalid_record");
			if (found.method !== only.method.name) return refused("wrong_method");
			if (!(await only.method.verify(request, found))) return refused("bad_credentials");
			return {
				kind: "authenticated",
				client: found,
				challenges: challenges.length > 0 ? challenges : every,
			};
		},
	};
}
