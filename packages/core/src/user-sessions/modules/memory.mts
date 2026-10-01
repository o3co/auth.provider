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

import { consoleLogger } from "../../logging/consoleLogger.mjs";
import type { Logger } from "../../logging/Logger.mjs";
import { defineModule } from "../../modules/manifest/define-module.mjs";
import { createInMemorySessionFamilyIndex } from "../memory/sessionFamilyIndex.mjs";
import { createInMemorySessionFederationIndex } from "../memory/sessionFederationIndex.mjs";
import { createInMemorySessionRPRegistry } from "../memory/sessionRPRegistry.mjs";
import { createInMemorySubjectRevocation } from "../memory/subjectRevocation.mjs";
import { createInMemorySubjectSessionIndex } from "../memory/subjectSessionIndex.mjs";
import { createInMemoryUserSessionStore } from "../memory/userSessionStore.mjs";

/**
 * Bundled module providing the in-memory user-session stores. Single-decision
 * wiring for the common case.
 *
 * For mixed wiring (e.g. memory userSessionStore + redis indexes), use
 * `overrideComponents` — `provides[K]` is skipped when an override is
 * supplied for K.
 */
export const memorySessionStoresModule = defineModule({
	name: "core-session-stores-memory",
	// What forks per replica, quoted into a refused multi-replica boot.
	replicaSafety: {
		unsafe: true,
		reason:
			"user sessions, RP registrations, family indexes and the subject-level revocation pair fork per replica — back-channel logout reaches only the replica that received it, so a logged-out session stays valid on the others, and a credential change enumerates and watermarks only the replica that handled it",
	},
	optional: ["logger"] as const,
	provides: {
		userSessionStore: () => createInMemoryUserSessionStore(),
		sessionRPRegistry: () => createInMemorySessionRPRegistry(),
		sessionFamilyIndex: () => createInMemorySessionFamilyIndex(),
		sessionFederationIndex: () => createInMemorySessionFederationIndex(),
		// Subject-keyed index + access-token watermark. Bundled here with
		// the other memory session stores so a single-node deployment gets
		// subject-level revocation by installing the module it already installs.
		subjectSessionIndex: () => createInMemorySubjectSessionIndex(),
		subjectRevocation: (deps: { readonly logger?: Logger }) =>
			createInMemorySubjectRevocation({ logger: deps.logger ?? consoleLogger }),
	} as never,
});
