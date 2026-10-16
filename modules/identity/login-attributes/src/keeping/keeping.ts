import { acceptedAttributes, userAttribute } from "@mod/users";
import type { AttributesKept, SourcedAttributes } from "../contract.ts";

/** The most UTF-8 bytes each text may hold, and how many groups a login may name; mail caps an email. */
const caps = { source: 128, name: 512, picture: 2048, group: 256, groups: 64 };
const named = new Set<string>(Object.values(userAttribute));

const within = (value: unknown, bytes: number): value is string =>
	typeof value === "string" &&
	value !== "" &&
	value.isWellFormed() &&
	Buffer.byteLength(value) <= bytes;
const isSource = (value: unknown): value is string =>
	within(value, caps.source) && !/\p{Cc}/u.test(value);
const isObject = (value: unknown): value is object => typeof value === "object" && value !== null;

/** The caps on what users accepts, by name; a name with none here has no cap. */
const fits: Readonly<Record<string, (value: never) => boolean>> = {
	[userAttribute.name]: (value: string) => within(value, caps.name),
	[userAttribute.picture]: (value: string) => within(value, caps.picture),
	[userAttribute.groups]: (list: readonly string[]) =>
		list.length <= caps.groups && list.every((group) => within(group, caps.group)),
};

/** The named values users accepts, each read once, then within their caps; nothing when none holds. */
function keptOf(source: string, values: object): SourcedAttributes | undefined {
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
 * What a login's attributes keep: a frozen copy of the named ones users accepts, within their caps,
 * dropped whole, never cut; none when the source or every value fails. Nothing given drops nothing.
 */
export function keptAttributes(given: unknown): AttributesKept {
	if (given === undefined) return Object.freeze({ kept: undefined, dropped: [], others: 0 });
	const { source, values } = (isObject(given) ? given : {}) as {
		source?: unknown;
		values?: unknown;
	};
	// Each part is judged once: the source, then whether the values are an object.
	const sourced = isSource(source);
	const offered = isObject(values) ? values : undefined;
	const kept = sourced && offered ? keptOf(source, offered) : undefined;
	const left = Object.keys(offered ?? {}).filter(
		(key) => !(kept && Object.hasOwn(kept.values, key)),
	);
	const names = left.filter((key) => named.has(key));
	return Object.freeze({
		kept,
		dropped: Object.freeze([...(sourced ? [] : ["source"]), ...names]),
		others: left.length - names.length,
	});
}
