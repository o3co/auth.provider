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

import { AdapterFactoryError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import { createFederationProviderFactory } from "#/federations/factory.mjs";

describe("createFederationProviderFactory", () => {
	it("returns an AdapterFactory with no registered types", () => {
		const factory = createFederationProviderFactory();
		expect(factory.registeredTypes()).toEqual([]);
	});

	it("rejects factory.create() for unknown type with AdapterFactoryError { reason: 'unknown', kind: 'FederationProvider' }", async () => {
		const factory = createFederationProviderFactory();
		await expect(factory.create({ type: "google", name: "google" })).rejects.toSatisfy(
			(err) =>
				err instanceof AdapterFactoryError &&
				err.reason === "unknown" &&
				err.kind === "FederationProvider",
		);
	});
});
