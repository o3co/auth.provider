import type { X509Certificate } from "node:crypto";
/**
 * A certificate's subject on one line, for a log field or a message:
 * `O=Example Corp, CN=client`.
 *
 * Node's `X509Certificate.subject` is OpenSSL's multi-line form — one RDN per
 * line — so a subject of more than one part, named as it comes, spans lines
 * in a log field or a message. The lines are joined with `", "`. That is
 * unambiguous: the form escapes a comma, a `+` or an ASCII control character
 * inside a value (`O=A\, B`), so a separator can only be one the join put
 * there. The order is the certificate's, the most significant RDN first.
 *
 * OpenSSL leaves a UTF-8 value's other characters as they are — a C1
 * control, U+2028, a bidi override — and caps nothing, so the line goes
 * through core's `lineSafeText`: each of those becomes `?`, a non-ASCII name
 * stays legible, and the subject is cut at 256 characters.
 */
export declare const subjectLine: (certificate: X509Certificate) => string;
//# sourceMappingURL=subject.d.mts.map