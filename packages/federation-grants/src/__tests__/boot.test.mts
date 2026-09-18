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
 * What `enabled = true` costs a composition (#593, §5 refusal 1).
 *
 * The rest of the boot refusals arrive with the routes that need them. This
 * one belongs here because it is the difference between the two branches this
 * commit has: an enabled deployment with nowhere to keep grants would answer
 * every request 503 after authenticating it, and would have accepted the
 * operator's `enabled = true` as if it meant something.
 */

import type { BootstrapMap } from "@o3co/auth-provider-core";
import {
	BootError,
	createApp,
	createMemoryFederationGrantStore,
	defineModule,
} from "@o3co/auth-provider-core";
import { makeValidCoreConfig } from "@o3co/auth-provider-core/testing";
import { describe, expect, it } from "vitest";
import { federationGrantsModules } from "#/index.mjs";

const storeModule = defineModule({
	name: "test-federation-grant-store",
	provides: { federationGrantStore: () => createMemoryFederationGrantStore() },
});

const boot = (enabled: unknown, withStore: boolean) =>
	createApp({
		modules: [...federationGrantsModules, ...(withStore ? [storeModule] : [])],
		bootstrapComponents: {
			config: { ...makeValidCoreConfig(), federationGrants: { enabled } },
			pathResolver: (s: string) => s,
		} as unknown as BootstrapMap,
	});

describe("enabling the feature", () => {
	it("refuses to boot with nowhere to keep grants", async () => {
		await expect(boot(true, false)).rejects.toThrow(/federationGrantStore/);
	});

	it("boots once a store is wired", async () => {
		const handle = await boot(true, true);
		expect(handle.components.federationGrantStore).toBeDefined();
		await handle.dispose();
	});

	it('reads the spellings an environment variable arrives in, so "true" enables', async () => {
		// #288: HOCON substitutes `${?FEDERATION_GRANTS_ENABLED}` as a string,
		// always. A bare `z.boolean()` here would leave an operator who
		// exported the documented variable with the feature silently off — the
		// one failure mode a secure default must not have, because it looks
		// like a working deployment.
		await expect(boot("true", false)).rejects.toThrow(/federationGrantStore/);
		await expect(boot("1", false)).rejects.toThrow(/federationGrantStore/);
	});

	it('reads "false", "0" and an exported-but-empty variable as off', async () => {
		for (const off of ["false", "0", ""]) {
			const handle = await boot(off, false);
			expect(handle.components.federationGrantStore).toBeUndefined();
			await handle.dispose();
		}
	});

	it("refuses a value that is neither, naming the spellings it accepts", async () => {
		// `z.coerce.boolean()` would have read "yes" as true and "no" as true
		// as well, so an operator switching the feature off would have switched
		// it on. The refusal carries the four real spellings, in the issue the
		// composed config schema raised.
		const error = await boot("yes", false).then(
			() => undefined,
			(thrown: unknown) => thrown,
		);
		expect(error).toBeInstanceOf(BootError);
		const { issues } = (error as BootError).details as {
			issues: readonly { readonly path: readonly PropertyKey[]; readonly message: string }[];
		};
		const issue = issues.find((i) => i.path.join(".") === "federationGrants.enabled");
		expect(issue?.message).toMatch(/"true", "false", "1" or "0"/);
	});
});
