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
 * The template's posture on session admission (the session-admission ADR's
 * D7). What it expects is its configuration's `sessionRequirements.expected`
 * — `[]` in the shipped `config/application.conf`, since `buildModules`
 * installs no module that registers a requirement — with `mfa` added when the
 * PARSED `mfa.mode` is not `off` (`expectedSessionRequirements`), never from
 * the raw `MFA_MODE`. The template installs no MFA module, so a mode that asks
 * for a second factor is refused at boot (`session-requirement-missing`)
 * rather than letting logins through on a password alone.
 */

import {
	BootError,
	defineModule,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { expectedSessionRequirements, readOwnLayers, resolveLayers } from "../configPath.mjs";
import {
	type Composition,
	compose,
	ownFiles,
	SINGLE_ENV,
} from "./all-modules-composition.fixture.mjs";

let current: Composition | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** The boot's refusal, or `undefined` when it booted (kept for disposal). */
const refusal = (composing: Promise<Composition>): Promise<unknown> =>
	composing.then(
		(composition) => {
			current = composition;
			return undefined;
		},
		(caught: unknown) => caught,
	);

describe("what the template expects of session admission", () => {
	it("is [] in the shipped configuration under the shipped mfa.mode, off, and the composition boots with it", async () => {
		const own = readOwnLayers(ownFiles(), { env: SINGLE_ENV });
		expect(resolveLayers(own, []).sessionRequirements).toEqual({ expected: [] });
		current = await compose();
		expect(current.config.mfa.mode).toBe("off");
		expect(current.config.sessionRequirements).toEqual({ expected: [] });
		expect([...(current.handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual(
			[],
		);
	});

	it.each(["optional", "required"] as const)(
		"adds mfa under MFA_MODE=%s, and is refused at boot while no MFA module registers it: session-requirement-missing",
		async (mode) => {
			const err = await refusal(compose({ env: { ...SINGLE_ENV, MFA_MODE: mode } }));
			expect(err).toBeInstanceOf(BootError);
			expect((err as BootError).reason).toBe("session-requirement-missing");
			expect((err as BootError).details).toMatchObject({
				configKey: "sessionRequirements.expected",
				missing: ["mfa"],
				declared: ["mfa"],
				registered: [],
			});
		},
	);

	it("keeps an operator's own list and adds mfa beside it, overwriting nothing", async () => {
		const err = await refusal(
			compose({
				env: { ...SINGLE_ENV, MFA_MODE: "required" },
				operatorHocon: 'sessionRequirements.expected = ["risk"]\n',
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			missing: ["risk", "mfa"],
			declared: ["risk", "mfa"],
		});
	});

	it("refuses the boot when the configuration expects mfa under mfa.mode = off and no installed module registers it", async () => {
		const err = await refusal(
			compose({ operatorHocon: 'sessionRequirements.expected = ["mfa"]\n' }),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			configKey: "sessionRequirements.expected",
			missing: ["mfa"],
		});
	});
});

describe("the requirement the template declares for MFA must be the declared second-factor authority", () => {
	/** A requirement registered as `mfa`, declaring the authority or not. */
	const named = (secondFactorAuthority: boolean): SessionRequirement => ({
		name: "mfa",
		secondFactorAuthority,
		reach: new Set(),
		stepUpPage: undefined,
		remediations: ["mfa.step_up"],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
	});

	it.each(["optional", "required"] as const)(
		"refuses the boot under MFA_MODE=%s when a module registers a requirement named mfa that does not declare the authority, disposing the handle",
		async (mode) => {
			const disposed: string[] = [];
			// Not MFA: named `mfa`, reaching nothing, bound to no MFA port.
			const namedMfa = defineModule({
				name: "deployment:named-mfa",
				provides: { namedMfaProbe: () => ({}) },
				lifecycle: {
					namedMfaProbe: {
						eager: true,
						cleanup: () => {
							disposed.push("namedMfaProbe");
						},
					},
				},
				contributes: { sessionRequirements: { mfa: () => named(false) } },
			} as never);
			const err = await refusal(
				compose({ env: { ...SINGLE_ENV, MFA_MODE: mode }, extraModules: () => [namedMfa] }),
			);
			expect(err).toBeInstanceOf(Error);
			expect((err as { reason?: unknown }).reason).toBe(
				"mfa-requirement-not-second-factor-authority",
			);
			expect(disposed).toEqual(["namedMfaProbe"]);
		},
	);

	it("boots under MFA_MODE=required when the requirement registered as mfa declares the authority, bound to the MFA ports", async () => {
		const authority = defineModule({
			name: "deployment:mfa",
			requires: ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"],
			contributes: { sessionRequirements: { mfa: () => named(true) } },
		} as never);
		current = await compose({
			env: { ...SINGLE_ENV, MFA_MODE: "required" },
			extraModules: () => [memoryMfaFactorStoreModule, memoryMfaTransactionStoreModule, authority],
		});
		expect(
			current.handle.components.sessionRequirementResolver?.get("mfa")?.secondFactorAuthority,
		).toBe(true);
	});

	it("asks nothing of a requirement named mfa under mfa.mode = off: the template declared none for MFA", async () => {
		const namedMfa = defineModule({
			name: "deployment:named-mfa",
			contributes: { sessionRequirements: { mfa: () => named(false) } },
		} as never);
		current = await compose({
			operatorHocon: 'sessionRequirements.expected = ["mfa"]\n',
			extraModules: () => [namedMfa],
		});
		expect(current.config.mfa.mode).toBe("off");
	});
});

describe("expectedSessionRequirements", () => {
	it("is the configuration's list, with mfa added once when the parsed mode is not off", () => {
		const of = (config: unknown) => expectedSessionRequirements(config as never);
		expect(of({ mfa: { mode: "off" }, sessionRequirements: { expected: ["risk"] } })).toEqual({
			expected: ["risk"],
		});
		expect(of({ mfa: { mode: "optional" }, sessionRequirements: { expected: ["risk"] } })).toEqual({
			expected: ["risk", "mfa"],
		});
		expect(of({ mfa: { mode: "required" }, sessionRequirements: { expected: ["mfa"] } })).toEqual({
			expected: ["mfa"],
		});
		expect(of({ mfa: { mode: "required" } })).toEqual({ expected: ["mfa"] });
	});

	it("keeps the configuration's list as written, repeats included, and adds mfa only when it is absent", () => {
		const of = (config: unknown) => expectedSessionRequirements(config as never);
		expect(
			of({ mfa: { mode: "required" }, sessionRequirements: { expected: ["risk", "risk"] } }),
		).toEqual({
			expected: ["risk", "risk", "mfa"],
		});
		expect(
			of({ mfa: { mode: "required" }, sessionRequirements: { expected: ["mfa", "risk", "mfa"] } }),
		).toEqual({
			expected: ["mfa", "risk", "mfa"],
		});
		expect(
			of({ mfa: { mode: "off" }, sessionRequirements: { expected: ["risk", "risk"] } }),
		).toEqual({
			expected: ["risk", "risk"],
		});
	});

	it("declares nothing when the configuration writes no list and the mode is off, so boot's own rule for an unwritten key applies", () => {
		expect(expectedSessionRequirements({ mfa: { mode: "off" } } as never)).toBeUndefined();
		expect(expectedSessionRequirements({} as never)).toBeUndefined();
	});

	it("reads the parsed mode alone: a mode that is none of the three is a RangeError naming mfa.mode, never read as off", () => {
		expect(() => expectedSessionRequirements({ mfa: { mode: "on" } } as never)).toThrow(
			/mfa\.mode/,
		);
	});
});
