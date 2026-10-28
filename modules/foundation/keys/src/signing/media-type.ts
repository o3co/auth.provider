/**
 * A JOSE header's `typ` as RFC 7515 compares a media type: its type alone, its parameters and the
 * space around it dropped, without case and without `application/`. The one reading of a type,
 * for every module that sorts tokens by theirs.
 */
export const mediaTypeOf = (typ: string): string =>
	(typ.split(";", 1)[0] ?? "")
		.trim()
		.toLowerCase()
		.replace(/^application\//, "");
