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
 * How long a single-use assertion may live: the one ceiling this server
 * holds every assertion whose `jti` it records to.
 *
 * An assertion recorded for single use — a `private_key_jwt` client
 * assertion, an ID-JAG — is remembered in the replay seen-set until its
 * `exp`, which is exactly how long it could be replayed. An `exp` with no
 * upper bound is therefore a replay record with none either. RFC 7523 §3
 * lets an authorization server reject an `exp` "unreasonably far in the
 * future"; the ID-JAG draft applies RFC 7521 §5.2's processing and names no
 * number of its own. This is the number: an assertion may run at most this
 * long past now (`exp − now`), and — the same hour the other way — may have
 * been issued at most this long ago (`iat` age). Client libraries mint
 * assertions that live a minute or ten; an hour leaves room for a client
 * whose clock runs ahead while keeping each record small.
 *
 * A plain RFC 7523 jwt-bearer assertion is not held to it: nothing of it is
 * recorded, and RFC 7523 gives its lifetime to the issuing authority.
 */
export const MAX_ASSERTION_LIFETIME_SECONDS = 3600;
