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
 * How the two MFA stores spell a caller's value inside a key or a hash field,
 * and the rule their key prefixes are held to. A subject, factor id or
 * transaction id is base64url of its JSON, as in the federation grant store,
 * so no brace a value carries can move a key's hash tag, and two values that
 * differ only in a lone surrogate (which UTF-8 turns into the same replacement
 * character) never share a key or a field.
 */
/** `value` as it appears inside a key or a field: base64url of its JSON. */
export const mfaKeyPart = (value) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
/**
 * Refuses, with a `RangeError` naming `store`, a key prefix that carries a
 * brace: it would open a hash tag of its own ahead of the subject's, and
 * every subject would land on the one Cluster slot the prefix names.
 */
export function checkMfaKeyPrefix(keyPrefix, store) {
    if (typeof keyPrefix !== "string" || keyPrefix.includes("{") || keyPrefix.includes("}")) {
        throw new RangeError(`${store}: keyPrefix must be a string without "{" or "}"`);
    }
    return keyPrefix;
}
