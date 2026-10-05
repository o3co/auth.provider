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
 * The per-session stores sessions joined and closed through before the
 * lifecycle record (`SessionRPRegistry`, `SessionFamilyIndex` with its end
 * mark, `SessionFederationIndex`), written beside the record while code that
 * knows only them still runs. A join writes their fence, the relying party
 * before the family, so a close that began through them lists it or refuses
 * it; a close writes their end mark before it lists them, so what joined
 * through them is closed too and nothing joins through them after. Only the
 * lifecycle service calls it.
 */

import {
	type RegisteredRP,
	type SessionFamilyIndex,
	type SessionFederationIndex,
	type SessionRPRegistry,
	supportsSessionEnd,
} from "../types.mjs";
import type { SessionParticipant } from "./types.mjs";

export interface SessionStoresBridgeStores {
	readonly sessionRPRegistry: SessionRPRegistry;
	readonly sessionFamilyIndex: SessionFamilyIndex;
	readonly sessionFederationIndex: SessionFederationIndex;
}

/**
 * `written`: the join is in the old stores. `refused`: the old end mark
 * refused the family — the session is ending — or, for a session being
 * adopted, the join carries no family to read the mark through and nothing
 * was written.
 */
export type BridgedJoin = "written" | "refused";

export interface SessionStoresBridge {
	/**
	 * Writes a join to the old stores: the relying party, then the family past
	 * the end mark, then the federation. `adopting`: the session has no
	 * lifecycle record, and is adopted only where no end mark can be present.
	 */
	join(
		sid: string,
		join: { readonly rp?: RegisteredRP; readonly familyId?: string; readonly federation?: string },
		expiresAt: Date,
		adopting: boolean,
	): Promise<BridgedJoin>;
	/** Writes the old end mark, then answers every participant the old stores hold. */
	close(sid: string, expiresAt: Date): Promise<readonly SessionParticipant[]>;
	/** Removes the session's entries from the old stores; the end mark stays. */
	remove(sid: string): Promise<void>;
}

const participant = (kind: SessionParticipant["kind"], id: string): SessionParticipant => ({
	kind,
	id,
	data: "",
});

export function createSessionStoresBridge(stores: SessionStoresBridgeStores): SessionStoresBridge {
	const { sessionRPRegistry, sessionFamilyIndex, sessionFederationIndex } = stores;
	return {
		async join(sid, join, expiresAt, adopting) {
			const marks = supportsSessionEnd(sessionFamilyIndex);
			// The mark is read only through the family's add.
			if (adopting && marks && join.familyId === undefined) return "refused";
			if (join.rp !== undefined) await sessionRPRegistry.registerRP(sid, join.rp, expiresAt);
			if (join.familyId !== undefined) {
				if (marks) {
					const added = await sessionFamilyIndex.addFamilyIdUnlessEnded(
						sid,
						join.familyId,
						expiresAt,
					);
					if (added === "ended") return "refused";
				} else {
					await sessionFamilyIndex.addFamilyId(sid, join.familyId, expiresAt);
				}
			}
			if (join.federation !== undefined) {
				await sessionFederationIndex.addFederation(sid, join.federation, expiresAt);
			}
			return "written";
		},

		async close(sid, expiresAt) {
			const families = supportsSessionEnd(sessionFamilyIndex)
				? await sessionFamilyIndex.endSession(sid, expiresAt)
				: await sessionFamilyIndex.listFamilyIds(sid);
			const [rps, federations] = await Promise.all([
				sessionRPRegistry.listRPs(sid),
				sessionFederationIndex.listFederations(sid),
			]);
			return [
				...rps.map((rp) => participant("rp", rp.clientId)),
				...families.map((familyId) => participant("family", familyId)),
				...federations.map((name) => participant("federation", name)),
			];
		},

		async remove(sid) {
			await Promise.all([
				sessionRPRegistry.removeBySid(sid),
				sessionFamilyIndex.removeBySid(sid),
				sessionFederationIndex.removeBySid(sid),
			]);
		},
	};
}
