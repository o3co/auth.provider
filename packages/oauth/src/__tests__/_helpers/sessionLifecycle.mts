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
 * Core's session lifecycle for a test composition that wires a user-session
 * store, which oauth's modules then require it beside: the lifecycle module,
 * the federation-token store it requires, and a session-close notifier for a
 * composition whose own modules contribute none (the oauth endpoints module
 * contributes one).
 */

import {
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionLifecycleStore,
	createInMemorySessionRPRegistry,
	createSessionLifecycle,
	defineModule,
	type FederationTokenStore,
	type Module,
	memoryFederationTokenStoreModule,
	type RefreshTokenFamilyRevocation,
	type SessionCloseNotifier,
	type SessionJoinOutcome,
	type SessionJoinRequest,
	type SessionLifecycle,
	sessionLifecycleModule,
	type UserSession,
	type UserSessionStore,
} from "@o3co/auth-provider-core";
import { vi } from "vitest";

const notifier: SessionCloseNotifier = { notify: async () => undefined };

/** Contributes a notifier that tells no relying party. */
export const testSessionCloseNotifierModule: Module = defineModule({
	name: "test:session-close-notifier",
	contributes: { sessionCloseNotifiers: { "test:session-close-notifier": () => notifier } },
});

/**
 * The lifecycle module and the federation-token store it requires, and, unless
 * `notifier` is false, a notifier: what a composition with a user-session store
 * adds to run oauth's modules.
 */
export const sessionLifecycleModules = (
	options: { readonly notifier?: boolean; readonly federationTokenStore?: boolean } = {},
): Module[] => [
	sessionLifecycleModule,
	...(options.federationTokenStore === false ? [] : [memoryFederationTokenStoreModule]),
	...(options.notifier === false ? [] : [testSessionCloseNotifierModule]),
];

/**
 * A session lifecycle whose `join` answers `answer` (`joined` by default) and
 * records each call, for a grant built by hand: what joined, and what it was
 * handed. Its other members are not expected to be called.
 */
export function joiningLifecycle(
	answer:
		| SessionJoinOutcome
		| ((sid: string, request: SessionJoinRequest) => Promise<SessionJoinOutcome>) = {
		outcome: "joined",
	},
) {
	const join = vi.fn(
		typeof answer === "function"
			? answer
			: async (_sid: string, _request: SessionJoinRequest) => answer,
	);
	const unexpected = async (): Promise<never> => {
		throw new Error("this test's session lifecycle only joins");
	};
	const lifecycle: SessionLifecycle = {
		open: unexpected,
		join,
		close: unexpected,
		liveness: unexpected,
		federations: unexpected,
		resumePending: unexpected,
	};
	return { lifecycle, join };
}

/**
 * A session lifecycle whose `liveness` answers from `store` as core's does for
 * an active record: `live` with the user session it reads, `not_live` when
 * there is none, and `unavailable` when the read throws. Its `federations`
 * answers `federations` (none by default), or what the function answers for
 * the sid, `unavailable` when it throws. With `onOutage: "reject"`, a read
 * that throws rejects instead, as a lifecycle the host fills may. Its other
 * members are not expected to be called.
 */
export function livenessOver(
	store: Partial<UserSessionStore>,
	federations: readonly string[] | ((sid: string) => Promise<readonly string[]>) = [],
	options: { readonly onOutage?: "answer" | "reject" } = {},
): SessionLifecycle {
	const rejects = options.onOutage === "reject";
	const unexpected = async (): Promise<never> => {
		throw new Error("this test's session lifecycle only answers liveness and federations");
	};
	return {
		open: unexpected,
		join: unexpected,
		close: unexpected,
		async liveness(sid) {
			let session: UserSession | null | undefined;
			try {
				session = await store.get?.(sid);
			} catch (err) {
				if (rejects) throw err;
				return { outcome: "unavailable" };
			}
			return session ? { outcome: "live", session } : { outcome: "not_live" };
		},
		async federations(sid) {
			if (typeof federations !== "function") return { outcome: "listed", federations };
			try {
				return { outcome: "listed", federations: await federations(sid) };
			} catch (err) {
				if (rejects) throw err;
				return { outcome: "unavailable" };
			}
		},
		resumePending: unexpected,
	};
}

/**
 * Core's session lifecycle over the stores a test composition hands it, with
 * in-memory stores for its own record and the per-session indexes, and no
 * relying party to tell: for a router built by hand whose logout closes.
 */
export function lifecycleOver(stores: {
	readonly userSessionStore: UserSessionStore;
	readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	readonly federationTokenStore: FederationTokenStore;
}): SessionLifecycle {
	return createSessionLifecycle({
		...stores,
		store: createInMemorySessionLifecycleStore(),
		sessionRPRegistry: createInMemorySessionRPRegistry(),
		sessionFamilyIndex: createInMemorySessionFamilyIndex(),
		sessionFederationIndex: createInMemorySessionFederationIndex(),
		retainMs: 3_600_000,
		logger: { warn: () => undefined, error: () => undefined },
	});
}
