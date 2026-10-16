import type { AllowanceLists } from "@mod/client-allowance";
import type { ClientRecord } from "@mod/clients";
import type { BuildContext, Log } from "@mod/kernel";
import {
	DestinationRefused,
	jsonObjectOf,
	type Narrower,
	type Outbound,
	type OutboundFailure,
	type OutboundResponse,
	OutboundUnavailable,
	outbound,
} from "@mod/outbound";
import type { Fetched } from "../fetching/fetching.ts";
import type { Settings } from "../section.ts";
import { recordOf } from "./document.ts";

/** A client id for one log field: no control characters, at most 200 characters (ids reach 256). */
const loggable = (text: string) => [...text.replace(/[\p{Cc}\p{Cf}]/gu, "")].slice(0, 200).join("");

/** RFC 9111 §5.2.2: the max age an answer grants, zero when it may not be kept. */
function maxAgeMsOf(answer: OutboundResponse): number | undefined {
	const directives = (answer.headers.get("cache-control") ?? "")
		.split(",")
		.map((d) => d.trim().toLowerCase());
	if (directives.includes("no-store") || directives.includes("no-cache")) return 0;
	const seconds = directives.find((d) => /^max-age=\d+$/.test(d))?.slice("max-age=".length);
	return seconds === undefined ? undefined : Number(seconds) * 1000;
}

const isJson = (answer: OutboundResponse) => {
	const [media = ""] = (answer.headers.get("content-type") ?? "").split(";");
	const type = media.trim().toLowerCase();
	return type === "application/json" || /^application\/[^/\s]+\+json$/.test(type);
};

const forgotten: ReadonlySet<OutboundFailure> = new Set(["timeout", "busy"]);

export interface ReadingParts {
	readonly outbound: Outbound;
	readonly narrower: Narrower;
	readonly ceiling: Omit<AllowanceLists, "grants">;
	readonly log: Log;
}

/** Fetches and judges one document; a refusal is remembered, a failure is not. */
export function readingWith({ outbound: out, narrower, ceiling, log }: ReadingParts) {
	const refused = (id: string, reason: string): Fetched<ClientRecord> => {
		log.warn("clients-cimd.document_refused", { client: loggable(id), reason });
		return { kind: "refused" };
	};
	/** What a fetch that threw says of the id: a refusal to remember, or a failure to forget. */
	const missed = (id: string, error: unknown): Fetched<ClientRecord> => {
		if (error instanceof DestinationRefused) return refused(id, error.reason);
		// Running out of time or places says nothing of the id, so it is fetched again next time.
		if (error instanceof OutboundUnavailable && !forgotten.has(error.failure)) {
			return refused(id, error.failure);
		}
		log.warn("clients-cimd.fetch_failed", { client: loggable(id) });
		return { kind: "failed" };
	};
	const answerOf = async (id: string): Promise<OutboundResponse | Fetched<ClientRecord>> => {
		try {
			return await out.fetch(id, { headers: { accept: "application/json" } }, narrower);
		} catch (error) {
			return missed(id, error);
		}
	};
	return async (id: string): Promise<Fetched<ClientRecord>> => {
		const answer = await answerOf(id);
		if ("kind" in answer) return answer;
		if (answer.status !== 200) return refused(id, `status ${answer.status}`);
		if (!isJson(answer)) return refused(id, "not a JSON object");
		const read = jsonObjectOf(answer);
		if (read.kind !== "object") return refused(id, "not a JSON object");
		const record = recordOf(new URL(id), read.value, ceiling);
		if ("refused" in record) return refused(id, record.refused);
		return { kind: "found", value: record, maxAgeMs: maxAgeMsOf(answer) };
	};
}

/** The reading over `outbound` and the operator's section. */
export async function readingOver(c: BuildContext<Settings>) {
	const s = c.section;
	return readingWith({
		outbound: await c.get(outbound),
		narrower: {
			...(s.allow.length > 0 ? { hosts: s.allow } : {}),
			maxBytes: s["max-bytes"],
			timeoutMs: s["timeout-ms"],
		},
		ceiling: { scopes: s.scopes, audiences: s.audiences },
		log: c.log,
	});
}
