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
 * Whether `record` covers a request for `scopes` at `nowMs`: it exists, has
 * not expired, and every requested scope is one the user agreed to. An
 * empty request is covered by any live record.
 */
export function consentCovers(record, scopes, nowMs = Date.now()) {
    if (record === null)
        return false;
    if (record.expiresAt !== undefined && record.expiresAt <= nowMs)
        return false;
    return scopes.every((scope) => record.scopes.includes(scope));
}
