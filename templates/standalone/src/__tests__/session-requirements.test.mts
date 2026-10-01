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
 * D7). What it expects is its configuration's `core.sessionRequirements.expected`
 * — `[]` in the shipped `config/application.conf`, since `buildModules`
 * installs no module that registers a requirement — with `mfa` added when
 * `mfa.mode` is not `off` (`expectedSessionRequirements`). The template reads
 * the mode itself (`readMfaMode`): from its own layers, where its
 * `application.conf` binds `MFA_MODE`, held to `off`, `optional` and
 * `required`, absent read as `off`. It installs no MFA module, so a mode that
 * asks for a second factor is refused at boot (`session-requirement-missing`)
 * rather than letting logins through on a password alone, and the `mfa`
 * section is not handed to boot. That reading goes at the MFA ADR's
 * build-order step 20, which installs the MFA module.
 */

import {
	BootError,
	defineModule,
	type Module,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import {
	expectedSessionRequirements,
	readMfaMode,
	readOwnLayers,
	readSwitches,
	resolveForBoot,
	resolveLayers,
} from "../configPath.mjs";
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
		expect(resolveLayers(own, []).core).toMatchObject({ sessionRequirements: { expected: [] } });
		expect(readMfaMode(readSwitches(own))).toBe("off");
		current = await compose();
		expect(current.config).not.toHaveProperty("mfa");
		expect(current.config.core?.sessionRequirements).toEqual({ expected: [] });
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
				configKey: "core.sessionRequirements.expected",
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
				operatorHocon: 'core.sessionRequirements.expected = ["risk"]\n',
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			missing: ["risk", "mfa"],
			declared: ["risk", "mfa"],
		});
	});

	it("refuses an MFA_MODE that is none of the three before boot, a RangeError naming mfa.mode that quotes nothing of it", async () => {
		const err = await refusal(compose({ env: { ...SINGLE_ENV, MFA_MODE: "sentinel-mode" } }));
		expect(err).toBeInstanceOf(RangeError);
		expect(err).not.toBeInstanceOf(BootError);
		expect((err as RangeError).message).toContain("mfa.mode");
		expect((err as RangeError).message).not.toContain("sentinel-mode");
	});

	it("refuses an mfa section written as a value, not a section of keys, before boot, naming mfa.mode, though MFA_MODE says required", async () => {
		for (const value of ["required", '"required"', "true", "1", "[required]", "null"]) {
			const err = await refusal(
				compose({
					env: { ...SINGLE_ENV, MFA_MODE: "required" },
					operatorHocon: `mfa = ${value}\n`,
				}),
			);
			expect(err, value).toBeInstanceOf(RangeError);
			expect(err, value).not.toBeInstanceOf(BootError);
			expect((err as RangeError).message, value).toContain("mfa.mode");
		}
	});

	it("hands boot an mfa section holding more than the mode, which boot names once as a section nothing owns", async () => {
		for (const hocon of ['mfa.mdoe = "required"\n', "mfa.factors.totp.enabled = false\n"]) {
			current = await compose({ operatorHocon: hocon });
			expect(current.resolved, hocon).toHaveProperty("mfa");
			const ignored = current.logger.lines.filter(
				(line) => line.args[1] === "config_sections_ignored",
			);
			expect(ignored, hocon).toHaveLength(1);
			expect(ignored[0]?.args[0], hocon).toEqual({ sections: ["mfa"] });
			await current.handle.dispose();
			current = undefined;
		}
	});

	it("refuses the boot when the configuration expects mfa under mfa.mode = off and no installed module registers it", async () => {
		const err = await refusal(
			compose({ operatorHocon: 'core.sessionRequirements.expected = ["mfa"]\n' }),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			configKey: "core.sessionRequirements.expected",
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
			operatorHocon: 'core.sessionRequirements.expected = ["mfa"]\n',
			extraModules: () => [namedMfa],
		});
		expect(
			current.handle.components.sessionRequirementResolver?.get("mfa")?.secondFactorAuthority,
		).toBe(false);
	});
});

describe("where the template reads mfa.mode from", () => {
	it("binds MFA_MODE in its own application.conf, with no default: absent, the section holds nothing", () => {
		const bound = (env: Readonly<Record<string, string>>) =>
			(readOwnLayers(ownFiles(), { env }).config.toObject() as { mfa?: unknown }).mfa;
		expect(bound({ ...SINGLE_ENV, MFA_MODE: "required" })).toEqual({ mode: "required" });
		expect(bound(SINGLE_ENV)).toEqual({});
	});

	it("hands boot no mfa section unless a loaded module reads it", () => {
		const own = readOwnLayers(ownFiles(), { env: { ...SINGLE_ENV, MFA_MODE: "off" } });
		const expected = expectedSessionRequirements(readSwitches(own));
		expect(resolveForBoot(own, [], expected)).not.toHaveProperty("mfa");
		// A module that reads the section: resolveForBoot reads its name and section alone.
		const reader = { name: "mfa", section: {} } as unknown as Module;
		expect((resolveForBoot(own, [reader], expected) as { mfa?: unknown }).mfa).toEqual({
			mode: "off",
		});
	});

	it("hands boot the mfa section when a loaded module's section sits under it, or moved from under it", () => {
		const own = readOwnLayers(ownFiles(), { env: { ...SINGLE_ENV, MFA_MODE: "off" } });
		const expected = expectedSessionRequirements(readSwitches(own));
		for (const module of [
			{ name: "nested", section: { at: "mfa.nested" } },
			{ name: "fork-totp", section: { relocatedFrom: ["mfa.factors.totp"] } },
			{ name: "fork-renamed", section: { relocatedFrom: { "mfa.factors.totp.window": "window" } } },
		]) {
			expect(
				(resolveForBoot(own, [module as unknown as Module], expected) as { mfa?: unknown }).mfa,
				module.name,
			).toEqual({ mode: "off" });
		}
	});
});

describe("readMfaMode", () => {
	it.each(["off", "optional", "required"] as const)("reads %s", (mode) => {
		expect(readMfaMode({ mfa: { mode } })).toBe(mode);
	});

	it.each([
		["no configuration", undefined],
		["no mfa section", {}],
		["no mode", { mfa: {} }],
	])("reads %s as off", (_label, config) => {
		expect(readMfaMode(config)).toBe("off");
	});

	it.each([
		["a string", "required"],
		["a boolean", true],
		["a number", 1],
		["a list", ["required"]],
		["null", null],
	])(
		"refuses an mfa section that is %s, not a section of keys, with the RangeError naming mfa.mode",
		(_label, mfa) => {
			expect(() => readMfaMode({ mfa })).toThrow(
				new RangeError('mfa.mode must be "off", "optional" or "required"'),
			);
		},
	);

	it.each([
		["a mode it does not know", "maybe"],
		["a casing slip", "Required"],
		["an empty string", ""],
		["null", null],
		["a non-string", true],
	])("refuses %s with a RangeError naming mfa.mode, never reading it as off", (_label, mode) => {
		expect(() => readMfaMode({ mfa: { mode } })).toThrow(
			new RangeError('mfa.mode must be "off", "optional" or "required"'),
		);
	});
});

describe("expectedSessionRequirements", () => {
	it("is the configuration's list, with mfa added once when the parsed mode is not off", () => {
		const of = (config: unknown) => expectedSessionRequirements(config as never);
		expect(
			of({ mfa: { mode: "off" }, core: { sessionRequirements: { expected: ["risk"] } } }),
		).toEqual({
			expected: ["risk"],
		});
		expect(
			of({ mfa: { mode: "optional" }, core: { sessionRequirements: { expected: ["risk"] } } }),
		).toEqual({
			expected: ["risk", "mfa"],
		});
		expect(
			of({ mfa: { mode: "required" }, core: { sessionRequirements: { expected: ["mfa"] } } }),
		).toEqual({
			expected: ["mfa"],
		});
		expect(of({ mfa: { mode: "required" } })).toEqual({ expected: ["mfa"] });
	});

	it("keeps the configuration's list as written, repeats included, and adds mfa only when it is absent", () => {
		const of = (config: unknown) => expectedSessionRequirements(config as never);
		expect(
			of({
				mfa: { mode: "required" },
				core: { sessionRequirements: { expected: ["risk", "risk"] } },
			}),
		).toEqual({
			expected: ["risk", "risk", "mfa"],
		});
		expect(
			of({
				mfa: { mode: "required" },
				core: { sessionRequirements: { expected: ["mfa", "risk", "mfa"] } },
			}),
		).toEqual({
			expected: ["mfa", "risk", "mfa"],
		});
		expect(
			of({ mfa: { mode: "off" }, core: { sessionRequirements: { expected: ["risk", "risk"] } } }),
		).toEqual({
			expected: ["risk", "risk"],
		});
	});

	it("declares nothing when the configuration writes no list and the mode is off, so boot's own rule for an unwritten key applies", () => {
		expect(expectedSessionRequirements({ mfa: { mode: "off" } } as never)).toBeUndefined();
		expect(expectedSessionRequirements({} as never)).toBeUndefined();
	});

	it("refuses a mode that is none of the three: a RangeError naming mfa.mode, never read as off", () => {
		expect(() => expectedSessionRequirements({ mfa: { mode: "on" } } as never)).toThrow(
			/mfa\.mode/,
		);
	});
});
