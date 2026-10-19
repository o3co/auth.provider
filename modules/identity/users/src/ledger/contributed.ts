import { deepFreeze, isUnavailable, type Log, Unavailable } from "@mod/kernel";
import {
	type BySubject,
	isAttributeValue,
	isWellFormedSubject,
	type Ledger,
	type Verified,
} from "../contract.ts";
import { none, type UserSource, unanswerable } from "../registered.ts";

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

function copyOf(given: unknown): unknown {
	try {
		return structuredClone(given);
	} catch {
		throw new Unavailable("users");
	}
}

/** A name the ledger wrote, safe for one log field. */
const loggable = (name: string) => [...name.replace(/[\p{Cc}\p{Cf}]/gu, "")].slice(0, 200).join("");

/** The attributes whose values users accepts; each other is left out, logged by name and never by value. */
function acceptedOf(attributes: Record<string, unknown>, log: Log): Record<string, unknown> {
	const accepted = (name: string, value: unknown) => {
		if (isAttributeValue(name, value)) return true;
		log.warn("users.attribute_dropped", { attribute: loggable(name) });
		return false;
	};
	return Object.fromEntries(
		Object.entries(attributes).filter(([name, value]) => accepted(name, value)),
	);
}

/** Reads a ledger's copied answer into a frozen user of its declared fields; a malformed answer, an ill-formed subject or another subject's user is unavailable. */
function readAnswer(answer: unknown, log: Log, askedSubject?: string): Verified {
	if (isObject(answer) && answer.kind === "none") return none;
	const user = isObject(answer) && answer.kind === "user" ? answer.user : undefined;
	if (!isObject(user) || !isObject(user.attributes) || typeof user.subject !== "string") {
		throw new Unavailable("users");
	}
	const { subject, attributes } = user;
	if (!isWellFormedSubject(subject) || (askedSubject !== undefined && subject !== askedSubject)) {
		throw new Unavailable("users");
	}
	return deepFreeze({ kind: "user", user: { subject, attributes: acceptedOf(attributes, log) } });
}

/** Any failure of the ledger is unavailable, never passed on as it came. */
async function fromLedger(call: () => Promise<BySubject>): Promise<unknown> {
	try {
		return await call();
	} catch (error) {
		throw isUnavailable(error) ? error : new Unavailable("users");
	}
}

export function contributedSource(ledger: Ledger, log: Log): UserSource {
	const { byUpstream } = ledger;
	const upstream = byUpstream
		? {
				byUpstream: async (idp: string, upstreamSubject: string) => {
					if (idp === "" || upstreamSubject === "") return none;
					const answer = copyOf(
						await fromLedger(() => byUpstream.call(ledger, idp, upstreamSubject)),
					);
					return readAnswer(answer, log);
				},
			}
		: { byUpstream: async () => none };
	return {
		verify: async (identifier, password) =>
			identifier === ""
				? none
				: readAnswer(copyOf(await fromLedger(() => ledger.verify(identifier, password))), log),
		bySubject: async (subject) => {
			if (!isWellFormedSubject(subject)) return none;
			const answer = copyOf(await fromLedger(() => ledger.bySubject(subject)));
			return isObject(answer) && answer.kind === "unanswerable"
				? unanswerable
				: readAnswer(answer, log, subject);
		},
		...upstream,
	};
}
