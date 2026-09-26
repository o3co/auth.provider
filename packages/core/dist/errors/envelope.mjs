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
/**
 * Construct an RFC 6749 §5.2 error envelope. Optional fields are omitted
 * (rather than serialized as `undefined`) so JSON consumers see a clean
 * shape — `JSON.stringify({ x: undefined })` does drop the key, but having
 * the helper pre-omit keeps the in-memory object consistent for tests
 * that snapshot the structure with `toEqual`.
 *
 * Empty-string `description` / `uri` are treated as omissions: RFC 6749
 * §5.2 specifies these as optional human-readable / URI fields, and an
 * empty string conveys no information while still serializing as a
 * present-but-empty value. Callers that need an explicit empty string
 * should construct the envelope literal directly.
 *
 * Contract scope: the three RFC 6749 §5.2 stock fields only (`error`,
 * `error_description`, `error_uri`). Extension fields (e.g. namespaced
 * sub-codes, rate-limit details) are not added here — pass through a
 * separate helper or a literal envelope object.
 *
 * @param error       Machine-readable error code (snake_case, e.g. `invalid_grant`).
 * @param description Optional human-readable detail. Empty string is dropped.
 * @param uri         Optional reference URL. Empty string is dropped.
 */
export function errorEnvelope(error, description, uri) {
    return {
        error,
        ...(description !== undefined && description !== "" ? { error_description: description } : {}),
        ...(uri !== undefined && uri !== "" ? { error_uri: uri } : {}),
    };
}
