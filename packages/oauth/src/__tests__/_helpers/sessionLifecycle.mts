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
 * Core's session lifecycle for oauth's tests, which every composition that
 * wires a user-session store now needs beside it:
 * - for a booted composition, the lifecycle module, the federation-token store
 *   it requires, and a session-close notifier where the composition's own
 *   modules contribute none (`sessionLifecycleModules`);
 * - for a route or grant built by hand, focused doubles — one that only joins
 *   and records each join (`joiningLifecycle`), and one that answers liveness
 *   and federations from a user-session store (`livenessOver`);
 * - and core's real lifecycle over in-memory stores, for a router whose
 *   logout closes (`lifecycleOver`).
 */

import {
	createInMemorySessionLifecycleStore,
	createSessionLifecycle,
	defineModule,
	type FederationTokenStore,
	type Module,
	memoryFederationTokenStoreModule,
	type RefreshTokenFamilyRevocation,
	type SessionCloseNotifier,
	type SessionFederations,
	type SessionJoinOutcome,
	type SessionJoinRequest,
	type SessionLifecycle,
	type SessionLiveness,
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
 * An answer outside the outcomes any route acts on, typed as `T`: what a
 * route's defensive fallback is pinned with. Core's lifecycle gives none, as
 * it rejects on an outage.
 */
export const outsideAnswer = <T,>(): T => ({ outcome: "unrecognised" }) as unknown as T;

/**
 * A session lifecycle whose `liveness` answers from `store` as core's does for
 * an active record: `live` with the user session it reads, `not_live` when
 * there is none. Its `federations` answers `federations` (none by default),
 * or what the function answers for the sid. A read that throws rejects with
 * that error, as core's lifecycle does on an outage; with
 * `onOutage: "answer"`, it answers outside the outcomes instead
 * (`outsideAnswer`), for a route's defensive fallback. Its other members are
 * not expected to be called.
 */
export function livenessOver(
	store: Partial<UserSessionStore>,
	federations: readonly string[] | ((sid: string) => Promise<readonly string[]>) = [],
	options: { readonly onOutage?: "answer" | "reject" } = {},
): SessionLifecycle {
	const rejects = options.onOutage !== "answer";
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
				return outsideAnswer<SessionLiveness>();
			}
			return session ? { outcome: "live", session } : { outcome: "not_live" };
		},
		async federations(sid) {
			if (typeof federations !== "function") return { outcome: "listed", federations };
			try {
				return { outcome: "listed", federations: await federations(sid) };
			} catch (err) {
				if (rejects) throw err;
				return outsideAnswer<SessionFederations>();
			}
		},
		resumePending: unexpected,
	};
}

/**
 * Core's session lifecycle over the stores a test composition hands it, with
 * an in-memory store for its own record, and no relying party to tell: for a
 * router built by hand whose logout closes. A session it closes is one it
 * opened: a sid with no record reads as closed.
 */
export function lifecycleOver(stores: {
	readonly userSessionStore: UserSessionStore;
	readonly refreshTokenFamilyRevocation: RefreshTokenFamilyRevocation;
	readonly federationTokenStore: FederationTokenStore;
}): SessionLifecycle {
	return createSessionLifecycle({
		...stores,
		store: createInMemorySessionLifecycleStore(),
		retainMs: 3_600_000,
		logger: { warn: () => undefined, error: () => undefined },
	});
}
