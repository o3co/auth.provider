/**
 * The one reading of "a control character" in text an operator configures —
 * an issuer, a label, a header: a C0 control character
 * (U+0000–U+001F), DEL (U+007F) or a C1 control character (U+0080–U+009F),
 * but those a rule allows. Such a character in a header splits it; in a log
 * line or a label it forges another.
 */
/** Whether `text` carries a C0 control character, DEL or a C1 control character, other than one `allowed`. */
export declare function hasControlCharacter(text: string, allowed?: ReadonlySet<string>): boolean;
//# sourceMappingURL=controlCharacters.d.mts.map