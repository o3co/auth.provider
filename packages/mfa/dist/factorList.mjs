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
/** `answer` as a fresh array of the records it holds; throws for anything but a list of records. */
export function readFactorList(answer) {
    if (!Array.isArray(answer)) {
        throw new TypeError("MfaFactorStore.list answered something that is not a list");
    }
    const records = [];
    for (let index = 0; index < answer.length; index++) {
        const entry = Object.hasOwn(answer, index) ? answer[index] : undefined;
        if (typeof entry !== "object" ||
            entry === null ||
            typeof entry.kind !== "string") {
            throw new TypeError("MfaFactorStore.list answered a list with an entry that is not a record");
        }
        records.push(entry);
    }
    return records;
}
