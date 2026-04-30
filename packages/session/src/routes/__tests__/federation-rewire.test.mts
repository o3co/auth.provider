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
import { describe, expect, it } from "vitest";
import { createRouter } from "../Federation.mjs";

const noop = () => undefined;
const stubRouter = {
	use(..._args: unknown[]) {
		return this;
	},
	get(..._args: unknown[]) {
		return this;
	},
	post(..._args: unknown[]) {
		return this;
	},
};
const stubExpress = {
	Router: () => stubRouter,
	json: () => noop,
	urlencoded: () => noop,
} as never;

describe("Federation.mts route rewire — federationRedirectPolicyResolver parameter", () => {
	it("createRouter accepts federationRedirectPolicyResolver parameter", () => {
		const mockPolicy = {
			validateRedirect: () => ({ ok: true as const, value: undefined }),
			resolveCallbackRedirect: () => ({ ok: true as const, value: "/" }),
		};
		const resolver = new Map([["google", mockPolicy]]);

		const stubSessionFederationIndex = {
			kind: "memory",
			async addFederation() {},
			async listFederations() {
				return [];
			},
			async removeFederation() {},
			async removeBySid() {},
		} as never;

		expect(() =>
			createRouter(stubExpress, {
				config: {} as never,
				federationProviders: new Map(),
				federationRedirectPolicyResolver: resolver as never,
				providerCallbackUrls: new Map(),
				userRepository: { authenticateByToken: async () => null } as never,
				userSessionStore: {} as never,
				sessionFederationIndex: stubSessionFederationIndex,
				federationTokenStore: {} as never,
			}),
		).not.toThrow();
	});
});
