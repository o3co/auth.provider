/** A segment as its bytes encode: base64url without padding, and no bits a decoder drops. */
export const canonical = (segment: string) =>
	/^[A-Za-z0-9_-]*$/.test(segment) &&
	Buffer.from(segment, "base64url").toString("base64url") === segment;

/**
 * Whether a compact JWS is written in its one form. A decoder drops a last character's spare bits,
 * so without this one token has many strings, and anything keyed by the string is slipped past.
 */
export const isCanonicalJws = (jws: string): boolean => {
	const segments = jws.split(".");
	return segments.length === 3 && segments.every(canonical);
};
