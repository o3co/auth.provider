import type { Json } from "@mod/store";

/** The member that marks an envelope, the record's format: version 1. */
const mark = "records:v";

/**
 * What a stored value holds: an envelope's value and subject, told by its exact shape alone (these
 * three members, the mark 1 and the subject a string), or any other value as it is, with none.
 */
export function opened(stored: Json | undefined): {
	readonly value: Json | undefined;
	readonly subject?: string;
} {
	if (stored !== null && typeof stored === "object" && !Array.isArray(stored)) {
		const held = stored as Readonly<Record<string, Json>>;
		const names = Object.keys(held);
		if (
			names.length === 3 &&
			held[mark] === 1 &&
			typeof held.subject === "string" &&
			Object.hasOwn(held, "value")
		) {
			return { value: held.value as Json, subject: held.subject };
		}
	}
	return { value: stored };
}

/** A value to store: in an envelope with its subject where it has one, else as it is. */
export const kept = (value: Json, subject: string | undefined): Json =>
	subject === undefined ? value : { [mark]: 1, subject, value };

/** An owner's value as given, refused where it holds the envelope's mark at its top. */
export function ownersValue<T extends Json>(value: T): T {
	if (value !== null && typeof value === "object" && !Array.isArray(value)) {
		if (Object.hasOwn(value, mark)) {
			throw new TypeError(`records: a value may not hold "${mark}" at its top`);
		}
	}
	return value;
}
