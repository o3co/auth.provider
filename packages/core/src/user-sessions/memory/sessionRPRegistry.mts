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

import type { RegisteredRP, SessionRPRegistry } from "../types.mjs";
import { createMemorySidHash } from "./internalSidHash.mjs";

/**
 * Defensive clone of a RegisteredRP. Constructs a fresh Date for `registeredAt`
 * so that callers cannot mutate the stored copy via the returned reference.
 * Per A4 §7.1 defensive-copy obligation.
 */
const cloneRP = (rp: RegisteredRP): RegisteredRP => ({
	clientId: rp.clientId,
	backchannelLogoutUri: rp.backchannelLogoutUri,
	backchannelLogoutSessionRequired: rp.backchannelLogoutSessionRequired,
	frontchannelLogoutUri: rp.frontchannelLogoutUri,
	frontchannelLogoutSessionRequired: rp.frontchannelLogoutSessionRequired,
	registeredAt: new Date(rp.registeredAt.getTime()),
});

/**
 * In-memory SessionRPRegistry. Wraps `createMemorySidHash<RegisteredRP>` keyed
 * by `clientId`. Provides idempotent upsert (replaces earlier registration when
 * back-channel logout URIs change between flows), expiry no-op on past
 * `expiresAt`, and defensive RP-clone on register and list.
 *
 * Per A4 §5.2 + §7.1 + §13.1.
 */
export function createInMemorySessionRPRegistry(): SessionRPRegistry {
	const hash = createMemorySidHash<RegisteredRP>((rp) => rp.clientId);

	return {
		kind: "memory",
		async registerRP(sid: string, rp: RegisteredRP, expiresAt: Date): Promise<void> {
			hash.setField(sid, cloneRP(rp), expiresAt);
		},
		async listRPs(sid: string): Promise<ReadonlyArray<RegisteredRP>> {
			return hash.listValues(sid).map(cloneRP);
		},
		async removeBySid(sid: string): Promise<void> {
			hash.removeBySid(sid);
		},
	};
}
