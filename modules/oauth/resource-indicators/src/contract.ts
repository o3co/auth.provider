/** An absolute URI's start (RFC 3986 §4.3): a scheme and its colon. */
const scheme = /^[A-Za-z][A-Za-z0-9+.-]*:/;
/** What no URI holds as written: whitespace and control characters. */
const unwritten = /[\s\x00-\x1f\x7f]/;

/**
 * Why a `resource` (RFC 8707 §2) is not one to take: not an absolute URI, or carrying a fragment;
 * none for one to take. Its form alone: whether it is an audience to issue is the caller's.
 */
export function resourceRefusal(value: string): string | undefined {
	if (!scheme.test(value) || unwritten.test(value) || !URL.canParse(value)) {
		return "resource is not an absolute URI";
	}
	if (value.includes("#")) return "resource carries a fragment";
	return undefined;
}
