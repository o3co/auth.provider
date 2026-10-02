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
 * The template's posture on session admission. What it expects is its
 * configuration's `core.sessionRequirements.expected`
 * — `[]` in the shipped `config/application.conf` — with `mfa` added when the
 * template's MFA switch, `mfaMode` (`MFA_MODE`), is not `off`
 * (`expectedSessionRequirements`); under that switch the template installs
 * the MFA module, whose requirement registers `mfa`. And what it hands boot
 * of the MFA module's section, `mfa`: nothing unless a loaded module owns it,
 * its mode written from the switch when the template installs MFA, and a
 * mode the configuration writes that the switch does not say refused.
 */

import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { BootError, type Module } from "@o3co/auth-provider-core";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "../buildModules.mjs";
import {
	expectedSessionRequirements,
	readOwnLayers,
	readSwitches,
	resolveForBoot,
	resolveLayers,
	type Switches,
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

/** What MFA on needs in production beside the switch: a key, and a mail relay. */
const MFA_ENV: Readonly<Record<string, string>> = {
	MFA_ENCRYPTION_KEY: Buffer.alloc(32, 9).toString("base64"),
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.auth.test",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@auth.test",
};

describe("what the template expects of session admission", () => {
	it("is [] in the shipped configuration under the shipped switch, off, and the composition boots with it", async () => {
		const own = readOwnLayers(ownFiles(), { env: SINGLE_ENV });
		expect(resolveLayers(own, []).core).toMatchObject({ sessionRequirements: { expected: [] } });
		expect(readSwitches(own).mfaMode).toBe("off");
		current = await compose();
		expect(current.config).not.toHaveProperty("mfa");
		expect(current.config.core?.sessionRequirements).toEqual({ expected: [] });
		expect([...(current.handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual(
			[],
		);
	});

	it.each(["optional", "required"] as const)(
		"adds mfa under MFA_MODE=%s, which the MFA module the template installs registers",
		async (mode) => {
			current = await compose({
				env: { ...SINGLE_ENV, ...MFA_ENV, MFA_MODE: mode },
				environment: "test",
			});
			expect(current.config.core?.sessionRequirements).toEqual({
				expected: ["mfa"],
				secondFactorAuthority: "mfa",
			});
			expect(
				[...(current.handle.components.sessionRequirementResolver?.entries() ?? [])].map(
					([name]) => name,
				),
			).toEqual(["mfa"]);
		},
	);

	it("keeps an operator's own list and adds mfa beside it, overwriting nothing", async () => {
		const err = await refusal(
			compose({
				env: { ...SINGLE_ENV, ...MFA_ENV, MFA_MODE: "required" },
				environment: "test",
				operatorHocon: 'core.sessionRequirements.expected = ["risk"]\n',
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("session-requirement-missing");
		expect((err as BootError).details).toMatchObject({
			missing: ["risk"],
			declared: ["risk", "mfa"],
		});
	});

	it("refuses the boot when the configuration expects mfa under the switch off: nothing registers it", async () => {
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

describe("what the template hands boot of the mfa section", () => {
	const ownUnder = (env: Readonly<Record<string, string>>, hocon?: string) =>
		readOwnLayers(hocon === undefined ? ownFiles() : [operatorLayer(hocon), ...ownFiles()], {
			env,
		});
	/** A module whose section is `mfa`: resolveForBoot reads its name and section alone. */
	const reader = { name: "mfa", section: {} } as unknown as Module;
	const mfaOf = (resolved: unknown) => (resolved as { mfa?: unknown }).mfa;

	it("hands none under the switch off unless a loaded module owns the section, whatever the configuration writes there", () => {
		const own = ownUnder(SINGLE_ENV, 'mfa.page.url = "/my-mfa"\nmfa.mdoe = "required"\n');
		const switches = readSwitches(own);
		expect(resolveForBoot(own, [], switches)).not.toHaveProperty("mfa");
		// A module the deployment adds that owns it: handed as written.
		expect(mfaOf(resolveForBoot(own, [reader], switches))).toEqual({
			page: { url: "/my-mfa" },
			mdoe: "required",
		});
	});

	it("hands it, owned by the MFA module the switch installs, with the mode written from the switch over the MFA package's default", () => {
		for (const mode of ["optional", "required"] as const) {
			// The switch written in a layer, MFA_MODE unset: the package's reference says off.
			const own = ownUnder(SINGLE_ENV, `mfaMode = "${mode}"\n`);
			const switches = readSwitches(own);
			const modules = buildModules(switches, { environment: "test" });
			expect(mfaOf(resolveForBoot(own, modules, switches)), mode).toMatchObject({ mode });
		}
	});

	it.each([
		["the switch off", {}, 'mfa.mode = "required"\n'],
		["the switch off, the mode optional", {}, 'mfa.mode = "optional"\n'],
		["MFA_MODE=optional", { MFA_MODE: "optional" }, 'mfa.mode = "required"\n'],
		["MFA_MODE=required", { MFA_MODE: "required" }, 'mfa.mode = "optional"\n'],
		["MFA_MODE=required, the section a value", { MFA_MODE: "required" }, 'mfa = "required"\n'],
	])(
		"refuses, under %s, an mfa.mode the configuration writes that the switch does not say, naming both keys and quoting nothing",
		(_label, env, hocon) => {
			const own = ownUnder({ ...SINGLE_ENV, ...env }, hocon);
			const switches = readSwitches(own);
			let err: unknown;
			try {
				resolveForBoot(own, [reader], switches);
			} catch (caught) {
				err = caught;
			}
			expect(err).toBeInstanceOf(RangeError);
			const message = (err as RangeError).message;
			expect(message).toContain("mfa.mode");
			expect(message).toContain("mfaMode");
			expect(message).not.toMatch(/"(?:off|optional|required)"/);
		},
	);

	it("accepts an mfa.mode the configuration writes that the switch says", () => {
		for (const [env, hocon] of [
			[{}, 'mfa.mode = "off"\n'],
			[{ MFA_MODE: "required" }, 'mfa.mode = "required"\n'],
		] as const) {
			const own = ownUnder({ ...SINGLE_ENV, ...env }, hocon);
			expect(() => resolveForBoot(own, [reader], readSwitches(own)), hocon).not.toThrow();
		}
	});

	it("is refused through the composition as through phase two: before boot, under the switch off", async () => {
		const err = await refusal(compose({ operatorHocon: 'mfa.mode = "required"\n' }));
		expect(err).toBeInstanceOf(RangeError);
		expect(err).not.toBeInstanceOf(BootError);
		expect((err as RangeError).message).toContain("mfaMode");
	});
});

describe("expectedSessionRequirements", () => {
	const of = (mfa: string, expected?: readonly string[], authority?: string) =>
		expectedSessionRequirements({
			mfaMode: mfa,
			...(expected === undefined && authority === undefined
				? {}
				: {
						core: {
							sessionRequirements: {
								...(expected === undefined ? {} : { expected }),
								...(authority === undefined ? {} : { secondFactorAuthority: authority }),
							},
						},
					}),
		} as unknown as Switches);
	const AUTHORITY = { secondFactorAuthority: "mfa" } as const;

	it("is the configuration's list, with mfa added once and named the second-factor authority when the switch is not off", () => {
		expect(of("off", ["risk"])).toEqual({ expected: ["risk"] });
		expect(of("optional", ["risk"])).toEqual({ expected: ["risk", "mfa"], ...AUTHORITY });
		expect(of("required", ["mfa"])).toEqual({ expected: ["mfa"], ...AUTHORITY });
		expect(of("required")).toEqual({ expected: ["mfa"], ...AUTHORITY });
	});

	it("keeps the configuration's list as written, repeats included, and adds mfa only when it is absent", () => {
		expect(of("required", ["risk", "risk"])).toEqual({
			expected: ["risk", "risk", "mfa"],
			...AUTHORITY,
		});
		expect(of("required", ["mfa", "risk", "mfa"])).toEqual({
			expected: ["mfa", "risk", "mfa"],
			...AUTHORITY,
		});
		expect(of("off", ["risk", "risk"])).toEqual({ expected: ["risk", "risk"] });
	});

	it("accepts a written second-factor authority the switch says, and keeps one written under the switch off", () => {
		expect(of("required", ["mfa"], "mfa")).toEqual({ expected: ["mfa"], ...AUTHORITY });
		expect(of("off", ["risk"], "risk")).toEqual({
			expected: ["risk"],
			secondFactorAuthority: "risk",
		});
	});

	it("refuses, with the switch on, a written second-factor authority other than mfa, naming the key and the switch and quoting nothing", () => {
		let err: unknown;
		try {
			of("required", ["mfa", "sentinel-requirement"], "sentinel-requirement");
		} catch (caught) {
			err = caught;
		}
		expect(err).toBeInstanceOf(RangeError);
		const message = (err as RangeError).message;
		expect(message).toContain("core.sessionRequirements.secondFactorAuthority");
		expect(message).toContain("mfaMode");
		expect(message).toContain("MFA_MODE");
		expect(message).not.toContain("sentinel-requirement");
	});

	it("declares nothing when the configuration writes no list and the switch is off, so boot's own rule for an unwritten key applies", () => {
		expect(of("off")).toBeUndefined();
	});
});

/** `text` in a file of its own, a layer above the composition's files. */
function operatorLayer(text: string): string {
	const file = join(mkdtempSync(join(tmpdir(), "session-requirements-")), "operator.conf");
	writeFileSync(file, text);
	return file;
}
