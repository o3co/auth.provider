import {
	type Constraint,
	type Named,
	type Scalar,
	type Selection,
	selectionLimits,
	type Target,
	withinLimits,
} from "@mod/claims-selection";

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** The acr a claims parameter asks for (OpenID Connect Core §5.5.1.1): its values, and whether they are essential. */
export interface AcrClaim {
	readonly values: readonly string[];
	readonly essential: boolean;
}

/** What a claims parameter asks that authorize acts on. */
export interface ClaimsRequest {
	/** Whether `id_token` asks for an essential `auth_time`. */
	readonly knownTime: boolean;
	/** The acr each member asks, kept apart. */
	readonly acr: readonly AcrClaim[];
	/** The `sub` values each member asks: the session's subject must be one of every list. */
	readonly subs: readonly (readonly string[])[];
	/** The claims it names beyond the scope, and their constraints, by target. */
	readonly selection: Selection;
}

const noTarget: Target = { names: [], constraints: [] };
export const noClaims: ClaimsRequest = {
	knownTime: false,
	acr: [],
	subs: [],
	selection: { idToken: noTarget, userinfo: noTarget },
};

const malformed = "malformed";
/** The members of an individual claim request it reads (§5.5.1); any other is passed over. */
interface Asked<T> {
	readonly essential: boolean;
	readonly value?: T;
	readonly values?: readonly T[];
}

/**
 * An individual claim request: `null`, or an object whose `essential` is a boolean and whose `value`
 * or non-empty `values` (not both, and no more than `most`) are of the kind `fits` takes; malformed
 * for any other shape.
 */
function individual<T>(
	entry: unknown,
	fits: (v: unknown) => v is T,
	most = Number.POSITIVE_INFINITY,
): Asked<T> | typeof malformed {
	if (entry === null) return { essential: false };
	if (!isObject(entry)) return malformed;
	const { essential, value, values } = entry;
	if (essential !== undefined && typeof essential !== "boolean") return malformed;
	if (value !== undefined && !fits(value)) return malformed;
	if (
		values !== undefined &&
		!(Array.isArray(values) && values.length > 0 && values.length <= most && values.every(fits))
	) {
		return malformed;
	}
	// Both together leave which one is asked unclear.
	if (value !== undefined && values !== undefined) return malformed;
	return {
		essential: essential === true,
		...(value !== undefined ? { value } : {}),
		...(values !== undefined ? { values: values as T[] } : {}),
	};
}

const isText = (v: unknown): v is string => typeof v === "string";
const isScalar = (v: unknown): v is Scalar =>
	(typeof v === "string" && v.length <= selectionLimits.valueLength) ||
	typeof v === "boolean" ||
	(typeof v === "number" && Number.isFinite(v));

/** The acr a member asks for: none where it names none. */
function acrOf(part: Record<string, unknown>): AcrClaim | undefined | typeof malformed {
	if (!Object.hasOwn(part, "acr")) return undefined;
	const asked = individual(part.acr, isText);
	if (asked === malformed) return malformed;
	return {
		values: [...(asked.value === undefined ? [] : [asked.value]), ...(asked.values ?? [])],
		essential: asked.essential,
	};
}

/** The `sub` values a member asks for: none where it names none, or names it with no value. */
function subOf(part: Record<string, unknown>): readonly string[] | undefined | typeof malformed {
	if (!Object.hasOwn(part, "sub")) return undefined;
	const asked = individual(part.sub, isText);
	if (asked === malformed) return malformed;
	const values = [...(asked.value === undefined ? [] : [asked.value]), ...(asked.values ?? [])];
	return values.length > 0 ? values : undefined;
}

/** Members this module reads for its own sake, never as claims to release. */
const read = new Set(["acr", "auth_time", "sub"]);

/** The claims a member names with a scope, and their constraints; claims without one are passed over. */
function targetOf(
	part: Record<string, unknown>,
	scopeOf: (claim: string) => string | undefined,
): Target | typeof malformed {
	const names: Named[] = [];
	const constraints: Constraint[] = [];
	for (const [name, entry] of Object.entries(part)) {
		if (read.has(name)) continue;
		const scope = scopeOf(name);
		if (scope === undefined) continue;
		// A claim kept for release is held to the bounds a selection keeps.
		const asked = individual(entry, isScalar, selectionLimits.values);
		if (asked === malformed) return malformed;
		names.push({ name, scope });
		if (asked.value !== undefined) constraints.push({ name, value: asked.value });
		if (asked.values !== undefined) constraints.push({ name, values: asked.values });
	}
	return { names, constraints };
}

/**
 * A claims parameter (OpenID Connect Core §5.5) read once: the acr, an essential auth_time and the
 * `sub` values each member asks, and, given the scope of each claim, the claims named beyond the
 * scope with their constraints. Malformed where it is no JSON object, a member it reads is of no
 * shape §5.5.1 gives, or what it names is past the bounds a selection keeps.
 */
export function claimsAsked(
	text: string,
	scopeOf?: (claim: string) => string | undefined,
): ClaimsRequest | typeof malformed {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return malformed;
	}
	if (!isObject(parsed)) return malformed;
	const parts = [parsed.id_token, parsed.userinfo].map((part) => (isObject(part) ? part : {}));
	const [idToken = {}, userinfo = {}] = parts;
	const asked = parts.map(acrOf);
	const subs = parts.map(subOf);
	if (asked.includes(malformed) || subs.includes(malformed)) return malformed;
	const targets = scopeOf ? [targetOf(idToken, scopeOf), targetOf(userinfo, scopeOf)] : [];
	if (targets.includes(malformed)) return malformed;
	const [idTarget = noTarget, userinfoTarget = noTarget] = targets as Target[];
	const selection = { idToken: idTarget, userinfo: userinfoTarget };
	if (!withinLimits(selection)) return malformed;
	const authTime = idToken.auth_time;
	return {
		knownTime: isObject(authTime) && authTime.essential === true,
		// Each request kept apart: an essential one is never met by another's voluntary values.
		acr: asked.filter((part): part is AcrClaim => part !== undefined && part !== malformed),
		subs: subs.filter(
			(part): part is readonly string[] => part !== undefined && part !== malformed,
		),
		selection,
	};
}
