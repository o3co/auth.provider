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
/** The reasons that say a responder did not answer usefully (see the module header). */
const OUTAGE_REASONS = new Set([
    "unparseable",
    "responder_error",
    "stale",
]);
/** `answer`, marked an outage when its reason says the responder did not answer usefully. */
export const markOutage = (answer) => !answer.ok && answer.outage === undefined && OUTAGE_REASONS.has(answer.reason)
    ? { ...answer, outage: true }
    : answer;
