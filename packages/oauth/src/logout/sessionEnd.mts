/*
 * Copyright 2026 1o1 Co. Ltd.
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
 * The order between a session's end and what joins it, and what a failure
 * between them leaves. A logout begins by marking the session ended
 * (`beginLogout`) before it reads the relying parties it tells; a code
 * exchange registers its relying party before its family joins the session
 * (`joinSession`). A relying party whose family joined is then in the
 * logout's listing, and one that comes after the mark is refused as ended
 * and serves no token. That inclusion — not the delivery of a logout token —
 * holds while the registry shows a completed registration to a later
 * listing and keeps it through that listing, the family index's mark is
 * authoritative and loses no acknowledged write, every join passes this
 * fence, and the clocks agree within the session's life. Without the
 * session-end capability there is no mark to order by: the logout reads,
 * and a join registers and adds, as the stores allow.
 */

import {
	type RegisteredRP,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	supportsSessionEnd,
} from "@o3co/auth-provider-core";

/** The stores a logout begins over. */
export interface LogoutBeginStores {
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionRPRegistry: SessionRPRegistry;
	readonly sessionFederationIndex: SessionFederationIndex;
}

/** A store that could not answer as a logout began, and what that left of the session. */
export interface LogoutBeginOutage {
	readonly store: "session_family_index" | "session_rp_registry" | "session_federation_index";
	readonly step: "endSession" | "list";
	/**
	 * `unchanged`: nothing was written. `half_ended`: the session is marked
	 * ended — its code exchanges are refused — and nothing else ran; it stays
	 * so until a retry completes the logout or the mark lapses. `unknown`: the
	 * mark's call failed, and the mark may have been written.
	 */
	readonly session: "unchanged" | "half_ended" | "unknown";
	readonly error: unknown;
	/** The federation index, when both listings failed; `store` then names the registry. */
	readonly alsoUnavailable?: {
		readonly store: "session_federation_index";
		readonly error: unknown;
	};
}

/**
 * A logout begun: the relying parties and federations to tell, and the
 * session's families as of its end, which `cascadeLogout` revokes without
 * reading them again (`undefined` without the session-end capability, when
 * it lists them itself). Or the outage.
 */
export type LogoutBegun =
	| {
			readonly outcome: "begun";
			readonly rps: ReadonlyArray<RegisteredRP>;
			readonly federations: ReadonlyArray<string>;
			readonly familyIds: ReadonlyArray<string> | undefined;
	  }
	| { readonly outcome: "unavailable"; readonly outage: LogoutBeginOutage };

/**
 * Begins a logout of `sid`: ends the session when the family index has the
 * session-end capability, then reads its relying parties and federations
 * together.
 */
export async function beginLogout(
	stores: LogoutBeginStores,
	sid: string,
	expiresAt: Date,
): Promise<LogoutBegun> {
	let familyIds: ReadonlyArray<string> | undefined;
	const index = stores.sessionFamilyIndex;
	const marks = supportsSessionEnd(index);
	if (supportsSessionEnd(index)) {
		try {
			familyIds = await index.endSession(sid, expiresAt);
		} catch (error) {
			return {
				outcome: "unavailable",
				outage: { store: "session_family_index", step: "endSession", session: "unknown", error },
			};
		}
	}
	const session = marks ? "half_ended" : "unchanged";
	const [rps, federations] = await Promise.allSettled([
		stores.sessionRPRegistry.listRPs(sid),
		stores.sessionFederationIndex.listFederations(sid),
	]);
	if (rps.status === "rejected") {
		return {
			outcome: "unavailable",
			outage: {
				store: "session_rp_registry",
				step: "list",
				session,
				error: rps.reason,
				...(federations.status === "rejected"
					? {
							alsoUnavailable: {
								store: "session_federation_index" as const,
								error: federations.reason,
							},
						}
					: {}),
			},
		};
	}
	if (federations.status === "rejected") {
		return {
			outcome: "unavailable",
			outage: {
				store: "session_federation_index",
				step: "list",
				session,
				error: federations.reason,
			},
		};
	}
	return { outcome: "begun", rps: rps.value, federations: federations.value, familyIds };
}

/** The stores a code exchange joins a session through. */
export interface SessionJoinStores {
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionRPRegistry: SessionRPRegistry;
}

/**
 * What joining answered: `joined`; `ended`, a logout began first and the
 * family did not join — nothing may be served for it; or the store that
 * could not answer — nothing may be served either. A relying party
 * registered before an `ended` or a failed add stays registered: removing
 * the session's registrations would remove earlier participants too. It
 * goes with the session's clean-up, or lapses with its TTL.
 */
export type SessionJoin =
	| { readonly outcome: "joined" }
	| { readonly outcome: "ended" }
	| {
			readonly outcome: "unavailable";
			readonly store: "session_rp_registry" | "session_family_index";
			readonly error: unknown;
	  };

/** Joins a code exchange's relying party and refresh-token family to `sid`, the relying party first. */
export async function joinSession(
	stores: SessionJoinStores,
	join: {
		readonly sid: string;
		readonly rp: RegisteredRP;
		readonly familyId: string;
		readonly expiresAt: Date;
	},
): Promise<SessionJoin> {
	try {
		await stores.sessionRPRegistry.registerRP(join.sid, join.rp, join.expiresAt);
	} catch (error) {
		return { outcome: "unavailable", store: "session_rp_registry", error };
	}
	const index = stores.sessionFamilyIndex;
	try {
		if (supportsSessionEnd(index)) {
			const added = await index.addFamilyIdUnlessEnded(join.sid, join.familyId, join.expiresAt);
			return { outcome: added === "ended" ? "ended" : "joined" };
		}
		await index.addFamilyId(join.sid, join.familyId, join.expiresAt);
		return { outcome: "joined" };
	} catch (error) {
		return { outcome: "unavailable", store: "session_family_index", error };
	}
}
