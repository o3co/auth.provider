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
 * Runs `cleanupRecords` in reverse order, best-effort: a cleanup that throws
 * does not stop the rest, and its error is returned, in the order run.
 * @internal
 */
export async function runCleanupsReverse(cleanupRecords) {
    const errors = [];
    for (let i = cleanupRecords.length - 1; i >= 0; i--) {
        // biome-ignore lint/style/noNonNullAssertion: i is bounded by cleanupRecords.length - 1
        const record = cleanupRecords[i];
        try {
            await record.cleanup(record.value);
        }
        catch (err) {
            errors.push({ module: record.module, componentKey: record.componentKey, error: err });
        }
    }
    return errors;
}
