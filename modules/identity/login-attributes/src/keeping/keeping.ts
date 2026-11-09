import { setting } from "@mod/kernel";
import { acceptedAttributes, userAttribute } from "@mod/users";
import { z } from "zod";
import type { AttributesKept, SourcedAttributes } from "../contract.ts";

/**
 * The caps an operator may set, in UTF-8 bytes and groups: the schema part a section takes. Each
 * bounds a session's record, so each has a ceiling.
 */
export const attributeCaps = z
	.strictObject({
		"groups-limit": z
			.number()
			.int()
			.min(1)
			.max(200)
			.prefault(64)
			.describe(
				"How many groups a login may name, from 1 to 200; more, and the groups are dropped whole.",
			),
		"group-limit": setting
			.size("B")
			.pipe(z.number().int().min(1).max(1024))
			.prefault("256B")
			.describe(
				"The longest group name, in UTF-8 bytes, from 1B to 1KiB; one longer, and the groups are dropped whole.",
			),
		"picture-limit": setting
			.size("B")
			.pipe(z.number().int().min(1).max(8192))
			.prefault("2KiB")
			.describe(
				"The longest picture URL, in UTF-8 bytes, from 1B to 8KiB; one longer is dropped whole.",
			),
	})
	.prefault({});

/** The caps as read. */
export type AttributeCaps = z.output<typeof attributeCaps>;

/** The most UTF-8 bytes a source and a name may hold; mail caps an email. */
const fixed = { source: 128, name: 512 };
const named = new Set<string>(Object.values(userAttribute));

const within = (value: unknown, bytes: number): value is string =>
	typeof value === "string" &&
	value !== "" &&
	value.isWellFormed() &&
	Buffer.byteLength(value) <= bytes;
const isSource = (value: unknown): value is string =>
	within(value, fixed.source) && !/\p{Cc}/u.test(value);
const isObject = (value: unknown): value is object => typeof value === "object" && value !== null;

/** The caps on what users accepts, by name; a name with none here has no cap. */
const fitsUnder = (caps: AttributeCaps): Readonly<Record<string, (value: never) => boolean>> => ({
	[userAttribute.name]: (value: string) => within(value, fixed.name),
	[userAttribute.picture]: (value: string) => within(value, caps["picture-limit"]),
	[userAttribute.groups]: (list: readonly string[]) =>
		list.length <= caps["groups-limit"] &&
		list.every((group) => within(group, caps["group-limit"])),
});

/** The named values users accepts, each read once, then within their caps; nothing when none holds. */
function keptOf(
	fits: ReturnType<typeof fitsUnder>,
	source: string,
	values: object,
): SourcedAttributes | undefined {
	const {
		[userAttribute.email]: email,
		[userAttribute.emailVerified]: verified,
		[userAttribute.name]: name,
		[userAttribute.picture]: picture,
		[userAttribute.groups]: groups,
	} = values as Record<string, unknown>;
	const accepted = acceptedAttributes({
		[userAttribute.email]: email,
		[userAttribute.emailVerified]: verified,
		[userAttribute.name]: name,
		[userAttribute.picture]: picture,
		[userAttribute.groups]: Array.isArray(groups) ? [...groups] : groups,
	});
	const kept = Object.entries(accepted).filter(
		([key, value]) => fits[key]?.(value as never) ?? true,
	);
	if (kept.length === 0) return undefined;
	return Object.freeze({ source, values: Object.freeze(Object.fromEntries(kept)) });
}

/**
 * What a login's attributes keep under `caps`: a frozen copy of the named ones users accepts, within
 * their caps, dropped whole, never cut; none when the source or every value fails. Nothing given
 * drops nothing.
 */
export function keepingWith(caps: AttributeCaps): (given: unknown) => AttributesKept {
	const fits = fitsUnder(caps);
	return (given) => {
		if (given === undefined) return Object.freeze({ kept: undefined, dropped: [], others: 0 });
		const { source, values } = (isObject(given) ? given : {}) as {
			source?: unknown;
			values?: unknown;
		};
		// Each part is judged once: the source, then whether the values are an object.
		const sourced = isSource(source);
		const offered = isObject(values) ? values : undefined;
		const kept = sourced && offered ? keptOf(fits, source, offered) : undefined;
		const left = Object.keys(offered ?? {}).filter(
			(key) => !(kept && Object.hasOwn(kept.values, key)),
		);
		const names = left.filter((key) => named.has(key));
		return Object.freeze({
			kept,
			dropped: Object.freeze([...(sourced ? [] : ["source"]), ...names]),
			others: left.length - names.length,
		});
	};
}

/** @deprecated Keeping under the default caps; use `keepingWith(attributeCaps.parse({}))`. */
export const keptAttributes = keepingWith(attributeCaps.parse({}));
