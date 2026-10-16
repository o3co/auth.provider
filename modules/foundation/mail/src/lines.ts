/** Characters that break or hide a line: controls and the Unicode line and paragraph separators. */
export const controls = /[\p{Cc}\p{Zl}\p{Zp}]/u;
/** The same, except line feed and tab, which a body may hold. */
export const bodyControls = /[[\p{Cc}\p{Zl}\p{Zp}]--[\n\t]]/v;
