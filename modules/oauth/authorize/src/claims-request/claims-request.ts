const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);
/** The acr a claims parameter asks for (OpenID Connect Core §5.5.1.1): its values, and whether they are essential. */
export interface AcrClaim {
	readonly values: readonly string[];
	readonly essential: boolean;
}

/**
 * The acr a request member of a claims parameter asks for: none where it names none; `null` asks
 * for one with nothing more; `value` or `values` name the acr; malformed for any other shape.
 */
function acrOf(part: unknown): AcrClaim | undefined | "malformed" {
	if (!isObject(part) || !Object.hasOwn(part, "acr")) return undefined;
	const asked = part.acr;
	if (asked === null) return { values: [], essential: false };
	if (!isObject(asked)) return "malformed";
	const { essential, value, values } = asked;
	if (essential !== undefined && typeof essential !== "boolean") return "malformed";
	if (value !== undefined && typeof value !== "string") return "malformed";
	if (
		values !== undefined &&
		!(Array.isArray(values) && values.length > 0 && values.every((v) => typeof v === "string"))
	) {
		return "malformed";
	}
	// Both together leave which one is asked unclear.
	if (value !== undefined && values !== undefined) return "malformed";
	return {
		values: [...(value === undefined ? [] : [value]), ...((values as string[] | undefined) ?? [])],
		essential: essential === true,
	};
}

/** A claims parameter is judged for acr and an essential auth_time; the other claims it names are not read here. */
export function claimsAsked(
	text: string,
): "malformed" | { readonly knownTime: boolean; readonly acr: readonly AcrClaim[] } {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch {
		return "malformed";
	}
	if (!isObject(parsed)) return "malformed";
	const asked = [acrOf(parsed.id_token), acrOf(parsed.userinfo)];
	if (asked.includes("malformed")) return "malformed";
	// Each request kept apart: an essential one is never met by another's voluntary values.
	const acr = asked.filter((part): part is AcrClaim => part !== undefined && part !== "malformed");
	const authTime = isObject(parsed.id_token) ? parsed.id_token.auth_time : undefined;
	return { knownTime: isObject(authTime) && authTime.essential === true, acr };
}
