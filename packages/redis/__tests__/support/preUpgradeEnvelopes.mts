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
 * `UserSession` envelopes as a release before `authentication` wrote them
 * (the MFA ADR's D9), byte for byte: what a live Redis holds at the upgrade.
 * Captured, not hand-built, so they are what the old writer wrote, key order
 * and all: `createRedisUserSessionStore` at 3673d4325 (the last commit before
 * the key), run against a client that recorded what `create` sent, for a
 * federated login (the upstream IdP's `hwk` beside `fed`) and a password
 * login. The expiry is 2099, so a read lands inside it whenever the test runs.
 */

/** A federated login: `amr` `["hwk", "fed"]`, no `authentication` key. */
export const PRE_UPGRADE_FEDERATED_ENVELOPE =
	'{"sid":"0b7f3c1e-6a52-4d0e-9f3a-2c1d5e8b7a90","sub":"u-alice","authTimeMs":1790557200000,"createdAtMs":1790580870903,"expiresAtMs":4070908800000,"claims":{"email":"alice@example.com","name":"Alice"},"amr":["hwk","fed"]}';

/** A password login: `amr` `["pwd"]`, no `authentication` key. */
export const PRE_UPGRADE_PASSWORD_ENVELOPE =
	'{"sid":"5d2e8f41-0c9b-4a7e-b3d6-7e1f2a9c4b08","sub":"u-bob","authTimeMs":1790557500000,"createdAtMs":1790580870903,"expiresAtMs":4070908800000,"claims":{"email":"bob@example.com"},"amr":["pwd"]}';

export const PRE_UPGRADE_FEDERATED_SID = "0b7f3c1e-6a52-4d0e-9f3a-2c1d5e8b7a90";
export const PRE_UPGRADE_PASSWORD_SID = "5d2e8f41-0c9b-4a7e-b3d6-7e1f2a9c4b08";
