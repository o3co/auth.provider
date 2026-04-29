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
import { expectTypeOf, test } from "vitest";
import type { AdapterFactory } from "../../adapters/AdapterFactory.mjs";
import type {
	CreateUserSessionInput,
	MutableUserSessionStore,
	RegisteredRP,
	SessionFamilyIndex,
	SessionFamilyIndexFactory,
	SessionFederationIndex,
	SessionFederationIndexFactory,
	SessionRPRegistry,
	SessionRPRegistryFactory,
	UserSession,
	UserSessionClaims,
	UserSessionStore,
	UserSessionStoreFactory,
} from "../types.mjs";
import type { ComponentMap } from "@o3co/auth-provider-core";

test("UserSessionStore exposes 3 methods (create/get/delete) — no mutation methods", () => {
	expectTypeOf<UserSessionStore["kind"]>().toEqualTypeOf<string>();
	expectTypeOf<UserSessionStore["create"]>().toEqualTypeOf<
		(input: CreateUserSessionInput) => Promise<void>
	>();
	expectTypeOf<UserSessionStore["get"]>().toEqualTypeOf<
		(sid: string) => Promise<UserSession | null>
	>();
	expectTypeOf<UserSessionStore["delete"]>().toEqualTypeOf<(sid: string) => Promise<void>>();
});

test("UserSessionStore does NOT expose registerRP/linkFamily/updateClaims/removeFederation", () => {
	expectTypeOf<UserSessionStore>().not.toHaveProperty("registerRP");
	expectTypeOf<UserSessionStore>().not.toHaveProperty("linkFamily");
	expectTypeOf<UserSessionStore>().not.toHaveProperty("updateClaims");
	expectTypeOf<UserSessionStore>().not.toHaveProperty("removeFederation");
});

test("CreateUserSessionInput drops federations field (now in SessionFederationIndex)", () => {
	expectTypeOf<CreateUserSessionInput>().toEqualTypeOf<{
		readonly sid: string;
		readonly sub: string;
		readonly authTime: Date;
		readonly expiresAt: Date;
		readonly claims: UserSessionClaims;
	}>();
});

test("UserSession value type has no activeRPs/familyIds/federations fields", () => {
	expectTypeOf<UserSession>().toEqualTypeOf<{
		readonly sid: string;
		readonly sub: string;
		readonly authTime: Date;
		readonly createdAt: Date;
		readonly expiresAt: Date;
		readonly claims: UserSessionClaims;
	}>();
});

test("SessionRPRegistry.registerRP requires expiresAt: Date positional argument", () => {
	expectTypeOf<SessionRPRegistry["registerRP"]>().toEqualTypeOf<
		(sid: string, rp: RegisteredRP, expiresAt: Date) => Promise<void>
	>();
	expectTypeOf<SessionRPRegistry["listRPs"]>().toEqualTypeOf<
		(sid: string) => Promise<ReadonlyArray<RegisteredRP>>
	>();
	expectTypeOf<SessionRPRegistry["removeBySid"]>().toEqualTypeOf<(sid: string) => Promise<void>>();
});

test("SessionFamilyIndex.addFamilyId requires expiresAt", () => {
	expectTypeOf<SessionFamilyIndex["addFamilyId"]>().toEqualTypeOf<
		(sid: string, familyId: string, expiresAt: Date) => Promise<void>
	>();
	expectTypeOf<SessionFamilyIndex["listFamilyIds"]>().toEqualTypeOf<
		(sid: string) => Promise<ReadonlyArray<string>>
	>();
});

test("SessionFederationIndex has 4 methods including per-element remove", () => {
	expectTypeOf<SessionFederationIndex["addFederation"]>().toEqualTypeOf<
		(sid: string, federationName: string, expiresAt: Date) => Promise<void>
	>();
	expectTypeOf<SessionFederationIndex["listFederations"]>().toEqualTypeOf<
		(sid: string) => Promise<ReadonlyArray<string>>
	>();
	expectTypeOf<SessionFederationIndex["removeFederation"]>().toEqualTypeOf<
		(sid: string, federationName: string) => Promise<void>
	>();
	expectTypeOf<SessionFederationIndex["removeBySid"]>().toEqualTypeOf<
		(sid: string) => Promise<void>
	>();
});

test("MutableUserSessionStore extends UserSessionStore with synchronous claims-only updater", () => {
	type Updater = MutableUserSessionStore["update"];
	expectTypeOf<Updater>().toEqualTypeOf<
		(
			sid: string,
			updater: (current: Readonly<UserSession>) => Readonly<UserSessionClaims> | null,
		) => Promise<UserSession | null>
	>();
});

test("ComponentMap declaration-merge: 4 store slots + 1 mutable slot, all optional", () => {
	expectTypeOf<ComponentMap["userSessionStore"]>().toEqualTypeOf<UserSessionStore | undefined>();
	expectTypeOf<ComponentMap["sessionRPRegistry"]>().toEqualTypeOf<
		SessionRPRegistry | undefined
	>();
	expectTypeOf<ComponentMap["sessionFamilyIndex"]>().toEqualTypeOf<
		SessionFamilyIndex | undefined
	>();
	expectTypeOf<ComponentMap["sessionFederationIndex"]>().toEqualTypeOf<
		SessionFederationIndex | undefined
	>();
	expectTypeOf<ComponentMap["mutableUserSessionStore"]>().toEqualTypeOf<
		MutableUserSessionStore | undefined
	>();
});

test("Factory aliases are AdapterFactory<T> over the 4 stores", () => {
	// Plan code used `toMatchTypeOf<{ register: (name, builder: unknown) => void }>()` but
	// that fails under strict function types (arrow-syntax parameter contravariance). Use
	// toEqualTypeOf<AdapterFactory<T>> which directly asserts the alias relationship.
	expectTypeOf<UserSessionStoreFactory>().toEqualTypeOf<AdapterFactory<UserSessionStore>>();
	expectTypeOf<SessionRPRegistryFactory>().toEqualTypeOf<AdapterFactory<SessionRPRegistry>>();
	expectTypeOf<SessionFamilyIndexFactory>().toEqualTypeOf<AdapterFactory<SessionFamilyIndex>>();
	expectTypeOf<SessionFederationIndexFactory>().toEqualTypeOf<AdapterFactory<SessionFederationIndex>>();
});

test("RegisteredRP exposes immutable fields with optional logout URIs", () => {
	expectTypeOf<RegisteredRP>().toEqualTypeOf<{
		readonly clientId: string;
		readonly backchannelLogoutUri?: string;
		readonly backchannelLogoutSessionRequired?: boolean;
		readonly frontchannelLogoutUri?: string;
		readonly frontchannelLogoutSessionRequired?: boolean;
		readonly registeredAt: Date;
	}>();
});
