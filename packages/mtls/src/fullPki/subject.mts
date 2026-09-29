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
 * `O=Example Corp, CN=client`, most significant RDN first.
 *
 * Node's `X509Certificate.subject` is OpenSSL's multi-line form, one RDN per
 * line. Joining with `", "` is unambiguous because the form escapes `,`, `+`
 * and ASCII controls inside a value (`O=A\, B`). OpenSSL leaves other
 * characters (C1 controls, U+2028, bidi overrides) as they are and caps
 * nothing, so core's `lineSafeText` turns those into `?`, keeps non-ASCII
 * names legible, and cuts at 256 characters.
 */
export const subjectLine = (certificate: X509Certificate): string =>
	lineSafeText(certificate.subject.split("\n").join(", "));
