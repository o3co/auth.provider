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
 * The live session `sid` names, as its subject; `not_live` when it is not
 * live (a session closing or closed, or gone); `no_answer` for any other
 * answer, which the caller treats as an outage. A `liveness` that rejects is
 * not caught here.
 */
export async function liveSessionSubject(lifecycle, sid) {
    const answer = await lifecycle.liveness(sid);
    if (answer.outcome === "live")
        return { subject: answer.session.sub };
    if (answer.outcome === "not_live")
        return "not_live";
    return "no_answer";
}
