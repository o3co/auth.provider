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
 * A `step_up` admission as a grant answers it: the session is live and
 * a requirement can be met by a trip a token endpoint cannot send anyone on,
 * so the client re-authenticates the user interactively — `invalid_grant`,
 * with the requirement named in `step_up`.
 */
export const stepUpRefusal = (requirement) => ({
    status: 400,
    error: "invalid_grant",
    errorDescription: `the session must step up through ${requirement}`,
    step_up: requirement,
});
/** The `step_up` member of a grant's error, when it carries one. */
export const stepUpOf = (result) => {
    const member = result.step_up;
    return typeof member === "string" && member.length > 0 ? member : undefined;
};
