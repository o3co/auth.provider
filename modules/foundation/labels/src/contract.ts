/** Controls and line separators break a line; directional marks and bidi controls reorder text. */
const unshowable = /[\p{Cc}\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u;

/**
 * Whether a page can show `text` as the name a user gave something, as it is: 1 to 64 code points,
 * well formed, with no control character, line separator, directional mark or bidi control.
 */
export const isLabel = (text: string): boolean =>
	text.length > 0 && [...text].length <= 64 && text.isWellFormed() && !unshowable.test(text);
