/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import type { X509Certificate } from "node:crypto";
import { lineSafeText } from "@o3co/auth-provider-core";

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
export const subjectLine = (certificate: X509Certificate): string =>
	lineSafeText(certificate.subject.split("\n").join(", "));
