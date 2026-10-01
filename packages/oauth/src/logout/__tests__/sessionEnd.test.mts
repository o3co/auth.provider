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
 * The order between a session's end and what joins it, on its own:
 * `beginLogout` marks the session ended before it reads the relying parties,
 * and `joinSession` registers a relying party before its family joins, so a
 * relying party whose family joined is in the logout's listing, and one that
 * comes after the mark is refused as ended. What each failure leaves behind
 * is answered, never assumed. Over core's memory stores, which have the
 * session-end capability.
 */

import {
	createInMemorySessionFamilyIndex,
	createInMemorySessionFederationIndex,
	createInMemorySessionRPRegistry,
	type RegisteredRP,
	type SessionFamilyIndex,
	type SupportsSessionEnd,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { beginLogout, joinSession, type LogoutBeginOutage } from "../sessionEnd.mjs";

const SID = "sid-1";
const EXPIRES_AT = new Date(Date.now() + 3_600_000);
const RP: RegisteredRP = {
	clientId: "client-1",
	backchannelLogoutUri: undefined,
	backchannelLogoutSessionRequired: undefined,
	frontchannelLogoutUri: undefined,
	frontchannelLogoutSessionRequired: undefined,
	registeredAt: new Date(),
};
const JOIN = { sid: SID, rp: RP, familyId: "fam-1", expiresAt: EXPIRES_AT };

const stores = () => ({
	sessionFamilyIndex: createInMemorySessionFamilyIndex(),
	sessionRPRegistry: createInMemorySessionRPRegistry(),
	sessionFederationIndex: createInMemorySessionFederationIndex(),
});

/** An index with only the port's three methods: no session-end capability. */
const withoutSessionEnd = (index: SessionFamilyIndex): SessionFamilyIndex => ({
	kind: index.kind,
	addFamilyId: vi.fn(index.addFamilyId),
	listFamilyIds: vi.fn(index.listFamilyIds),
	removeBySid: vi.fn(index.removeBySid),
});

afterEach(() => {
	vi.restoreAllMocks();
});

describe("joinSession, then beginLogout", () => {
	it("a relying party whose family joined before the logout began is in its listing, with the family", async () => {
		const s = stores();
		expect(await joinSession(s, JOIN)).toEqual({ outcome: "joined" });
		const begun = await beginLogout(s, SID, EXPIRES_AT);
		if (begun.outcome !== "begun") throw new Error(`expected begun, got ${JSON.stringify(begun)}`);
		expect(begun.rps.map((rp) => rp.clientId)).toEqual(["client-1"]);
		expect(begun.federations).toEqual([]);
		expect(begun.familyIds).toEqual(["fam-1"]);
	});

	it("a join after the logout began answers ended", async () => {
		const s = stores();
		await beginLogout(s, SID, EXPIRES_AT);
		expect(await joinSession(s, JOIN)).toEqual({ outcome: "ended" });
	});

	it("an RP registry entry that expires during the listing is not listed though its family is: the inclusion holds only while the registration outlives the listing", async () => {
		// One expiry for both stores; the family index reads its clock at 9999,
		// the registry at 10001 — clock skew, or the expiry reached mid-listing.
		const s = stores();
		const expiresAt = new Date(10_000);
		const clock = { now: 5_000 };
		vi.spyOn(Date, "now").mockImplementation(() => clock.now);
		expect(await joinSession(s, { ...JOIN, expiresAt })).toEqual({ outcome: "joined" });
		const endSession = s.sessionFamilyIndex.endSession.bind(s.sessionFamilyIndex);
		const listRPs = s.sessionRPRegistry.listRPs.bind(s.sessionRPRegistry);
		const begun = await beginLogout(
			{
				...s,
				sessionFamilyIndex: Object.assign(Object.create(s.sessionFamilyIndex), {
					endSession: (sid: string, until: Date) => {
						clock.now = 9_999;
						return endSession(sid, until);
					},
				}) as SessionFamilyIndex & SupportsSessionEnd,
				sessionRPRegistry: {
					...s.sessionRPRegistry,
					listRPs: (sid: string) => {
						clock.now = 10_001;
						return listRPs(sid);
					},
				},
			},
			SID,
			expiresAt,
		);
		if (begun.outcome !== "begun") throw new Error(`expected begun, got ${JSON.stringify(begun)}`);
		expect(begun.familyIds).toEqual(["fam-1"]);
		expect(begun.rps).toEqual([]);
	});
});

describe("beginLogout — what a failure leaves", () => {
	it("a mark that cannot be written leaves the session's state unknown, and nothing is read", async () => {
		const s = stores();
		const boom = new Error("down");
		const listRPs = vi.spyOn(s.sessionRPRegistry, "listRPs");
		vi.spyOn(s.sessionFamilyIndex, "endSession").mockRejectedValue(boom);
		expect(await beginLogout(s, SID, EXPIRES_AT)).toEqual({
			outcome: "unavailable",
			outage: {
				store: "session_family_index",
				step: "endSession",
				left: "unknown",
				error: boom,
			},
		});
		expect(listRPs).not.toHaveBeenCalled();
	});

	it("a mark written before its call failed — as a store that marks and then lists — is why unknown is not unchanged: a later join answers ended", async () => {
		const s = stores();
		const endSession = s.sessionFamilyIndex.endSession.bind(s.sessionFamilyIndex);
		vi.spyOn(s.sessionFamilyIndex, "endSession").mockImplementation(async (sid, until) => {
			await endSession(sid, until);
			throw new Error("the listing after the mark failed");
		});
		const begun = await beginLogout(s, SID, EXPIRES_AT);
		expect(begun).toMatchObject({ outcome: "unavailable", outage: { left: "unknown" } });
		expect(await joinSession(s, JOIN)).toEqual({ outcome: "ended" });
	});

	it("a relying-party listing that fails after the mark leaves the session half-ended: joins answer ended", async () => {
		const s = stores();
		const boom = new Error("registry down");
		vi.spyOn(s.sessionRPRegistry, "listRPs").mockRejectedValue(boom);
		expect(await beginLogout(s, SID, EXPIRES_AT)).toEqual({
			outcome: "unavailable",
			outage: { store: "session_rp_registry", step: "list", left: "half_ended", error: boom },
		});
		expect(await joinSession(s, JOIN)).toEqual({ outcome: "ended" });
	});

	it("a federation listing that fails after the mark leaves the session half-ended, naming the federation index", async () => {
		const s = stores();
		const federationsDown = new Error("index down");
		vi.spyOn(s.sessionFederationIndex, "listFederations").mockRejectedValue(federationsDown);
		expect(await beginLogout(s, SID, EXPIRES_AT)).toEqual({
			outcome: "unavailable",
			outage: {
				store: "session_federation_index",
				step: "list",
				left: "half_ended",
				error: federationsDown,
			},
		});
	});

	it("both listings failing name the registry, with the federation index as alsoUnavailable", async () => {
		const s = stores();
		const rpsDown = new Error("registry down");
		const federationsDown = new Error("index down");
		vi.spyOn(s.sessionFederationIndex, "listFederations").mockRejectedValue(federationsDown);
		vi.spyOn(s.sessionRPRegistry, "listRPs").mockRejectedValue(rpsDown);
		expect(await beginLogout(s, SID, EXPIRES_AT)).toEqual({
			outcome: "unavailable",
			outage: {
				store: "session_rp_registry",
				step: "list",
				left: "half_ended",
				error: rpsDown,
				alsoUnavailable: { store: "session_federation_index", error: federationsDown },
			},
		});
	});

	it("without the session-end capability: nothing is marked, and the families are left for the cascade to read", async () => {
		const index = withoutSessionEnd(createInMemorySessionFamilyIndex());
		const s = { ...stores(), sessionFamilyIndex: index };
		await s.sessionRPRegistry.registerRP(SID, RP, EXPIRES_AT);
		await s.sessionFederationIndex.addFederation(SID, "google", EXPIRES_AT);
		const begun = await beginLogout(s, SID, EXPIRES_AT);
		expect(begun).toMatchObject({
			outcome: "begun",
			federations: ["google"],
			familyIds: undefined,
		});
		expect(index.listFamilyIds).not.toHaveBeenCalled();
	});

	it("without the session-end capability, a failed listing leaves the session unchanged", async () => {
		const s = {
			...stores(),
			sessionFamilyIndex: withoutSessionEnd(createInMemorySessionFamilyIndex()),
		};
		const boom = new Error("registry down");
		vi.spyOn(s.sessionRPRegistry, "listRPs").mockRejectedValue(boom);
		expect(await beginLogout(s, SID, EXPIRES_AT)).toEqual({
			outcome: "unavailable",
			outage: { store: "session_rp_registry", step: "list", left: "unchanged", error: boom },
		});
	});
});

describe("joinSession", () => {
	it("without the session-end capability: registers the relying party and adds the family, joined", async () => {
		const index = withoutSessionEnd(createInMemorySessionFamilyIndex());
		const s = { ...stores(), sessionFamilyIndex: index };
		expect(await joinSession(s, JOIN)).toEqual({ outcome: "joined" });
		expect(index.addFamilyId).toHaveBeenCalledWith(SID, "fam-1", EXPIRES_AT);
		expect((await s.sessionRPRegistry.listRPs(SID)).map((rp) => rp.clientId)).toEqual(["client-1"]);
	});

	it("a registry that cannot register is unavailable naming it, and the family is not added", async () => {
		const s = stores();
		const boom = new Error("down");
		vi.spyOn(s.sessionRPRegistry, "registerRP").mockRejectedValue(boom);
		expect(await joinSession(s, JOIN)).toEqual({
			outcome: "unavailable",
			store: "session_rp_registry",
			step: "register",
			error: boom,
		});
		expect(await s.sessionFamilyIndex.listFamilyIds(SID)).toEqual([]);
	});

	it("a family index that cannot add is unavailable naming it; the relying party registered first stays, and nothing of the session is removed", async () => {
		const s = stores();
		const earlier: RegisteredRP = { ...RP, clientId: "client-0" };
		await s.sessionRPRegistry.registerRP(SID, earlier, EXPIRES_AT);
		const boom = new Error("down");
		vi.spyOn(s.sessionFamilyIndex, "addFamilyIdUnlessEnded").mockRejectedValue(boom);
		const removeBySid = vi.spyOn(s.sessionRPRegistry, "removeBySid");
		expect(await joinSession(s, JOIN)).toEqual({
			outcome: "unavailable",
			store: "session_family_index",
			step: "add",
			error: boom,
		});
		expect((await s.sessionRPRegistry.listRPs(SID)).map((rp) => rp.clientId)).toEqual([
			"client-0",
			"client-1",
		]);
		expect(removeBySid).not.toHaveBeenCalled();
	});
});

describe("LogoutBeginOutage", () => {
	it("pairs each store with its own step and the states it can leave", () => {
		const outages: LogoutBeginOutage[] = [
			{ store: "session_family_index", step: "endSession", left: "unknown", error: null },
			{ store: "session_rp_registry", step: "list", left: "half_ended", error: null },
			{ store: "session_federation_index", step: "list", left: "unchanged", error: null },
			// @ts-expect-error — the family index's only step is endSession
			{ store: "session_family_index", step: "list", left: "unknown", error: null },
			// @ts-expect-error — a failed mark leaves the session unknown, never unchanged
			{ store: "session_family_index", step: "endSession", left: "unchanged", error: null },
			// @ts-expect-error — a listing does not mark: its state is never unknown
			{ store: "session_rp_registry", step: "list", left: "unknown", error: null },
		];
		expect(outages).toHaveLength(6);
	});
});
