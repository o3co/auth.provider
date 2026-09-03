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
 * Picks UserSessionClaims-shaped fields off a User. Used by LOCAL and
 * FEDERATION login paths to seed the session's claims envelope.
 *
 * Moved from `@o3co/auth-provider-core/user-sessions/claims.mts` (deleted in
 * Phase 8d's T29) into the session package because it has only 2 callers,
 * both inside this package.
 */
export function extractUserClaims(user) {
    const c = {};
    if (typeof user.email === "string")
        c.email = user.email;
    if (typeof user.emailVerified === "boolean")
        c.emailVerified = user.emailVerified;
    if (typeof user.name === "string")
        c.name = user.name;
    if (typeof user.picture === "string")
        c.picture = user.picture;
    if (Array.isArray(user.groups) && user.groups.every((g) => typeof g === "string")) {
        c.groups = user.groups;
    }
    return c;
}
