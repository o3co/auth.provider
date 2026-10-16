/** Whitespace and control characters, which nothing consent keeps or sends as written holds. */
export const spaceOrControl = /[\s\p{Cc}]/u;

/** The text as an https URL; refused when it holds what the parser would drop, as it is kept as written. */
export const httpsUrl = (text: string) => {
	const parsed = spaceOrControl.test(text) ? null : URL.parse(text);
	return parsed?.protocol === "https:" ? parsed : undefined;
};
