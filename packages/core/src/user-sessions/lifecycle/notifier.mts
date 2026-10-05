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
 * The contract the session lifecycle tells a relying party through that a
 * session it joined has closed. Core decides when and for which cause; the
 * module that issues to relying parties implements it and decides how a
 * notice is delivered.
 */

import type { SessionCloseCause } from "./types.mjs";

/** One relying party to tell that one session has closed. */
export interface SessionCloseNotice {
	readonly sid: string;
	readonly sub: string;
	/** The relying party's `client_id`, as it joined the session. */
	readonly clientId: string;
	/** Why the session closed: its first close's cause. */
	readonly cause: SessionCloseCause;
}

/**
 * Tells relying parties that a session they joined has closed. Filled in the
 * `sessionCloseNotifier` slot; a composition with relying parties must fill
 * it.
 */
export interface SessionCloseNotifier {
	/**
	 * Tells `notice.clientId` that the session closed. Resolves once the
	 * notice is settled: delivered, or given up by the notifier's own policy
	 * (a relying party with nowhere to tell, or one that answered it will not
	 * take it). Rejects only when it should be tried again: the work stays
	 * pending, and a later close of the session or the sweep calls it again.
	 * It may be called more than once for one notice, concurrently too.
	 */
	notify(notice: SessionCloseNotice): Promise<void>;
}

// ComponentMap declaration-merge: an optional slot.
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		readonly sessionCloseNotifier?: SessionCloseNotifier;
	}
}
