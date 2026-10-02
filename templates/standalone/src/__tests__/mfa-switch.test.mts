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
 * The template's MFA switch, `mfaMode` (`MFA_MODE`): `off`, the
 * default, installs nothing of MFA; `optional` and `required` install the MFA
 * package's modules — the MFA module, the TOTP, recovery-code and email
 * factors, the operator reset — with the session package's login completion
 * and the two MFA stores `adapters` selects, and declare `mfa` in
 * `core.sessionRequirements.expected`. Booted through the all-modules
 * fixture, and, where the shipped user repository or the development files
 * are the question, the way `app.mts` boots.
 */

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type AppConfig,
	BootError,
	createApp,
	defineModule,
	memoryMfaFactorStoreModule,
	memoryMfaTransactionStoreModule,
	memoryRefreshTokenFamilyStoreModule,
	type SessionRequirement,
} from "@o3co/auth-provider-core";
import { MFA_DEVELOPMENT_SAMPLE_KEY, mfaModules, mfaResetModule } from "@o3co/auth-provider-mfa";
import { loginCompletionModule } from "@o3co/auth-provider-session";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { buildModules } from "#/buildModules.mjs";
import { readOwnLayers, readSwitches, resolveConfigPaths, resolveForBoot } from "#/configPath.mjs";
import {
	ALICE,
	authorize,
	type Composition,
	compose,
	contributionNames,
	cookiesOf,
	createRecordingLogger,
	ISSUER,
	ownFiles,
	type RecordingLogger,
	SINGLE_ENV,
	WEB,
} from "./all-modules-composition.fixture.mjs";

/** 32 bytes, base64: a key of the deployment's own for the MFA key ring. */
const MFA_KEY = Buffer.alloc(32, 9).toString("base64");

/** What a deployment exports to turn MFA on in production: the switch, its key, and the SMTP relay. */
const MAIL_ENV: Readonly<Record<string, string>> = {
	MFA_ENCRYPTION_KEY: MFA_KEY,
	STANDARD_SMTP_MAIL_SENDER_HOST: "smtp.auth.test",
	STANDARD_SMTP_MAIL_SENDER_FROM: "auth@auth.test",
};

const on = (mode: "optional" | "required", extra: Readonly<Record<string, string>> = {}) => ({
	...SINGLE_ENV,
	...MAIL_ENV,
	MFA_MODE: mode,
	...extra,
});

/** Every module the switch installs, with core's memory MFA stores (the shipped selection). */
const MFA_MODULE_NAMES = [
	...mfaModules().map((m) => m.name),
	mfaResetModule.name,
	loginCompletionModule.name,
	memoryMfaFactorStoreModule.name,
	memoryMfaTransactionStoreModule.name,
].sort();

let current: Composition | undefined;
let handles: { dispose(): Promise<void> }[] = [];

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
	for (const handle of handles) await handle.dispose();
	handles = [];
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

/** An error's message with every cause's under it. */
const textOf = (err: unknown): string => {
	const parts: string[] = [];
	for (let at: unknown = err; at instanceof Error; at = at.cause) parts.push(at.message);
	return parts.join(" <- ");
};

/** The warn lines named `event`. */
const warned = (logger: RecordingLogger, event: string) =>
	logger.lines.filter((line) => line.level === "warn" && line.args[1] === event);

describe("the switch is the template's own key, mfaMode, bound to MFA_MODE", () => {
	it("is off unless MFA_MODE says otherwise", () => {
		const switches = (env: Readonly<Record<string, string>>) =>
			readSwitches(readOwnLayers(ownFiles(), { env })).mfaMode;
		expect(switches(SINGLE_ENV)).toBe("off");
		for (const mode of ["off", "optional", "required"] as const) {
			expect(switches({ ...SINGLE_ENV, MFA_MODE: mode })).toBe(mode);
		}
	});

	it("refuses an MFA_MODE that is none of the three before boot, a RangeError naming mfaMode and MFA_MODE that quotes nothing of it", async () => {
		const err = await refusal(compose({ env: on("required", { MFA_MODE: "sentinel-mode" }) }));
		expect(err).toBeInstanceOf(RangeError);
		expect(err).not.toBeInstanceOf(BootError);
		expect((err as RangeError).message).toContain("mfaMode");
		expect((err as RangeError).message).toContain("MFA_MODE");
		expect((err as RangeError).message).not.toContain("sentinel-mode");
	});
});

describe("MFA_MODE unset: nothing of MFA is installed", () => {
	it("lists no MFA module, registers no requirement, and hands boot no mfa section", async () => {
		current = await compose();
		const names = current.modules.map((m) => m.name);
		expect(names.filter((name) => MFA_MODULE_NAMES.includes(name))).toEqual([]);
		expect(current.resolved).not.toHaveProperty("mfa");
		expect([...(current.handle.components.sessionRequirementResolver?.entries() ?? [])]).toEqual(
			[],
		);
		expect(current.handle.components.mfaReset).toBeUndefined();
	});

	it("keeps the shipped urn:o3co:acr:mfa entry out of discovery without a warning: no second factor is reachable", async () => {
		current = await compose();
		const doc = await request(current.app).get("/.well-known/openid-configuration");
		expect(doc.body.acr_values_supported ?? []).not.toContain("urn:o3co:acr:mfa");
		expect(warned(current.logger, "acr_value_unsatisfiable")).toEqual([]);
	});

	it("boots in production with no SMTP relay: nothing reads the mail sender", async () => {
		current = await compose({ env: SINGLE_ENV, environment: "production" });
		expect(current.modules.map((m) => m.name)).toContain("standard-smtp-mail-sender");
	});
});

describe.each(["optional", "required"] as const)("MFA_MODE=%s", (mode) => {
	it("installs every MFA module once, the stores adapters selects, and the subject-revocation service once", async () => {
		current = await compose({ env: on(mode) });
		const names = current.modules.map((m) => m.name);
		expect(names.filter((name) => MFA_MODULE_NAMES.includes(name)).sort()).toEqual(
			MFA_MODULE_NAMES,
		);
		expect(names.filter((name) => name === "subject-revocation-service")).toHaveLength(1);
		expect(new Set(names).size).toBe(names.length);
		expect(current.handle.components.mfaReset).toBeDefined();
	});

	it("hands the deployment's logger to every MFA module that answers a request", async () => {
		current = await compose({ env: on(mode) });
		const answering = current.modules.filter(
			(m) => MFA_MODULE_NAMES.includes(m.name) && contributionNames(m, "routes").length > 0,
		);
		expect(answering.map((m) => m.name)).toEqual(["mfa"]);
		for (const module of answering) {
			expect([...(module.requires ?? []), ...(module.optional ?? [])], module.name).toContain(
				"logger",
			);
		}
	});

	it("declares mfa, which the MFA module registers as the second-factor authority, and writes mfa.mode from the switch", async () => {
		current = await compose({ env: on(mode) });
		expect(current.config.core?.sessionRequirements).toEqual({ expected: ["mfa"] });
		const mfa = current.handle.components.sessionRequirementResolver?.get("mfa");
		expect(mfa?.secondFactorAuthority).toBe(true);
		expect((current.config as unknown as { mfa: { mode: unknown } }).mfa.mode).toBe(mode);
	});

	it("advertises urn:o3co:acr:mfa, with no acr line at boot", async () => {
		current = await compose({ env: on(mode) });
		const doc = await request(current.app).get("/.well-known/openid-configuration");
		expect(doc.body.acr_values_supported).toContain("urn:o3co:acr:mfa");
		expect(
			current.logger.lines.filter((line) => line.args[1] === "acr_value_unsatisfiable"),
		).toEqual([]);
	});

	it.each([
		["off", {}],
		["on", { MFA_EMAIL_FACTOR_ENABLED: "true" }],
	])(
		"is refused in production without an SMTP relay, the email factor %s, naming STANDARD_SMTP_MAIL_SENDER_HOST",
		async (_factor, email) => {
			const err = await refusal(
				compose({
					env: { ...SINGLE_ENV, MFA_MODE: mode, MFA_ENCRYPTION_KEY: MFA_KEY, ...email },
				}),
			);
			expect(err).toBeInstanceOf(BootError);
			expect(textOf(err)).toContain("STANDARD_SMTP_MAIL_SENDER_HOST");
		},
	);

	it("boots with the email factor on and the SMTP relay set", async () => {
		current = await compose({ env: on(mode, { MFA_EMAIL_FACTOR_ENABLED: "true" }) });
		expect(current.handle.components.mfaFactorResolver?.get("email")).toBeDefined();
	});
});

describe("the MFA stores follow adapters", () => {
	const listed = (env: Readonly<Record<string, string>>) =>
		buildModules(readSwitches(readOwnLayers(ownFiles(), { env })), {
			environment: "production",
			refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
		}).map((m) => m.name);

	it("lists the Redis ones, and the shared Redis clients, under redis", () => {
		const names = listed(
			on("required", {
				ADAPTERS_MFA_FACTOR_STORE: "redis",
				ADAPTERS_MFA_TRANSACTION_STORE: "redis",
			}),
		);
		expect(names).toContain("redis-mfa-factor-store");
		expect(names).toContain("redis-mfa-transaction-store");
		expect(names).toContain("redis-clients");
		expect(names).not.toContain(memoryMfaFactorStoreModule.name);
		expect(names).not.toContain(memoryMfaTransactionStoreModule.name);
	});

	it("lists no Redis MFA store and opens no shared Redis socket for them while MFA is off", () => {
		const names = listed({
			...SINGLE_ENV,
			ADAPTERS_MFA_FACTOR_STORE: "redis",
			ADAPTERS_MFA_TRANSACTION_STORE: "redis",
		});
		expect(names.filter((name) => /mfa/.test(name))).toEqual([]);
		expect(names).not.toContain("redis-clients");
	});

	it("keeps the factors in the Store under store, over the user repository's credential, and boots", async () => {
		current = await compose({
			env: on("optional", {
				ADAPTERS_MFA_FACTOR_STORE: "store",
				FOUNDATION_MFA_FACTOR_STORE_LIST_URL: "https://store.auth.test/mfa/list",
				FOUNDATION_MFA_FACTOR_STORE_CREATE_URL: "https://store.auth.test/mfa/create",
				FOUNDATION_MFA_FACTOR_STORE_UPDATE_URL: "https://store.auth.test/mfa/update",
				FOUNDATION_MFA_FACTOR_STORE_DELETE_URL: "https://store.auth.test/mfa/delete",
				REPOSITORIES_USER_HTTP_BEARER_TOKEN:
					"0328d706529061d93abd6d826e09ef0f0a1e71a12af813b29e5cd2977b7dc63a",
			}),
		});
		const names = current.modules.map((m) => m.name);
		expect(names).toContain("foundation-mfa-factor-store");
		expect(names).not.toContain(memoryMfaFactorStoreModule.name);
	});

	it("refuses the Store under store with a URL missing, naming it", async () => {
		const err = await refusal(
			compose({ env: on("optional", { ADAPTERS_MFA_FACTOR_STORE: "store" }) }),
		);
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain("foundation-mfa-factor-store");
	});

	it("refuses the memory ones under core.deployment.mode = multi, by name", async () => {
		const err = await refusal(
			compose({
				env: on("required", { CORE_DEPLOYMENT_MODE: "multi" }),
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain(memoryMfaFactorStoreModule.name);
	});
});

describe("MFA_MODE=required never lets a password alone sign in", () => {
	it("interrupts the password login, opening no session /authorize accepts", async () => {
		current = await compose({ env: on("required") });
		const csrf = await request(current.app).get("/session/csrf");
		const res = await request(current.app)
			.post("/session/login")
			.set("Cookie", cookiesOf(csrf))
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(res.status).toBe(403);
		expect(["mfa_enrollment_required", "mfa_required"]).toContain(res.body.error);
		const answer = await authorize(current.app, [...cookiesOf(csrf), ...cookiesOf(res)]);
		const location = String(answer.headers.location ?? "");
		expect(location.startsWith(WEB.redirectUri)).toBe(false);
		expect(location).not.toMatch(/[?&]code=/);
	});

	/** A requirement a deployment registers, declaring the second-factor authority or not. */
	const requirement = (name: string, secondFactorAuthority: boolean): SessionRequirement => ({
		name,
		secondFactorAuthority,
		reach: new Set(),
		stepUpPage: undefined,
		remediations: [],
		hintKeys: [],
		admit: async () => ({ outcome: "met" }),
	});

	it("refuses a second requirement named mfa", async () => {
		const impostor = defineModule({
			name: "deployment:named-mfa",
			contributes: { sessionRequirements: { mfa: () => requirement("mfa", false) } },
		} as never);
		const err = await refusal(compose({ env: on("required"), extraModules: () => [impostor] }));
		expect(err).toBeInstanceOf(BootError);
	});

	it("refuses a second requirement declaring the second-factor authority: duplicate-second-factor-authority", async () => {
		const rival = defineModule({
			name: "deployment:rival",
			requires: ["mfaFactorResolver", "mfaFactorStore", "mfaTransactionStore"],
			contributes: { sessionRequirements: { rival: () => requirement("rival", true) } },
		} as never);
		const err = await refusal(
			compose({
				env: on("required"),
				operatorHocon: 'core.sessionRequirements.expected = ["rival"]\n',
				extraModules: () => [rival],
			}),
		);
		expect(err).toBeInstanceOf(BootError);
		expect((err as BootError).reason).toBe("duplicate-second-factor-authority");
	});
});

describe("mfa.storeTimeoutMs", () => {
	/** As the MFA module reads it: an environment variable's digits are its number. */
	const storeTimeoutMs = (c: Composition) =>
		Number((c.config as unknown as { mfa: { storeTimeoutMs: unknown } }).mfa.storeTimeoutMs);

	it("is the MFA package's default, the user directory's default timeout, and MFA_STORE_TIMEOUT_MS sets it", async () => {
		current = await compose({ env: on("optional") });
		expect(storeTimeoutMs(current)).toBe(5000);
		await current.handle.dispose();
		current = await compose({ env: on("optional", { MFA_STORE_TIMEOUT_MS: "9000" }) });
		expect(storeTimeoutMs(current)).toBe(9000);
	});

	it("is refused above 37 500 ms, naming the key", async () => {
		const err = await refusal(compose({ env: on("optional", { MFA_STORE_TIMEOUT_MS: "37501" }) }));
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain("mfa.storeTimeoutMs");
	});
});

describe("the development sample key", () => {
	it("is refused under CONFIG_ENV=production", async () => {
		const err = await refusal(
			compose({ env: on("required", { MFA_ENCRYPTION_KEY: MFA_DEVELOPMENT_SAMPLE_KEY }) }),
		);
		expect(err).toBeInstanceOf(BootError);
		expect(textOf(err)).toContain("MFA_ENCRYPTION_KEY");
		expect(textOf(err)).not.toContain(MFA_DEVELOPMENT_SAMPLE_KEY);
	});
});

// ---------------------------------------------------------------------------
// As app.mts boots: the shipped user repository, the development files
// ---------------------------------------------------------------------------

const configDir = fileURLToPath(new URL("../../config", import.meta.url));
const signingKey = generateKeyPairSync("ed25519", {
	publicKeyEncoding: { type: "spki", format: "pem" },
	privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const clientsFile = (() => {
	const file = join(mkdtempSync(join(tmpdir(), "mfa-switch-")), "clients.yaml");
	writeFileSync(file, "");
	return file;
})();

/** One replica, every store in memory, MFA required. */
const SHIPPED_ENV: Readonly<Record<string, string>> = {
	OAUTH_JWT_ISSUER: ISSUER,
	KEY_STORE_LOCAL_PRIVATE_KEY: signingKey.privateKey,
	KEY_STORE_LOCAL_PUBLIC_KEY: signingKey.publicKey,
	SESSION_STORE_SECRET: "mfa-switch-session-secret.at-least-32-bytes.ok",
	SESSION_STORE_SECURE: "false",
	SESSION_STORE_NAME: "auth.session",
	CORE_DEPLOYMENT_MODE: "single",
	SESSION_STORE_STORAGE_TYPE: "memory",
	ADAPTERS_USER_SESSION_STORES: "memory",
	ADAPTERS_RATE_LIMITER: "memory",
	ADAPTERS_CODE_REPOSITORY: "memory",
	ADAPTERS_ACCESS_TOKEN_DENYLIST: "memory",
	ADAPTERS_REPLAY_SEEN_SET: "memory",
	REPOSITORIES_CLIENT_YAML_PATH: clientsFile,
	ADAPTERS_USER_REPOSITORY: "http",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_URL: "https://store.auth.test/authenticate",
	REPOSITORIES_USER_HTTP_AUTHENTICATE_BY_TOKEN_URL: "https://store.auth.test/by-token",
	MFA_MODE: "required",
};

/** Boots the template's own files for `configEnv` under `env`, as `app.mts` does. */
async function bootShipped(
	env: Readonly<Record<string, string>>,
	configEnv: string,
): Promise<{ readonly logger: RecordingLogger; readonly config: AppConfig }> {
	const { applicationConfPath, envConfPath } = resolveConfigPaths(configDir, configEnv);
	const own = readOwnLayers([envConfPath, applicationConfPath], { env });
	const switches = readSwitches(own);
	const logger = createRecordingLogger();
	const modules = buildModules(switches, {
		environment: configEnv,
		logger,
		refreshTokenFamilyModules: [memoryRefreshTokenFamilyStoreModule],
	});
	const handle = await createApp({
		modules,
		bootstrapComponents: {
			config: resolveForBoot(own, modules, switches),
			pathResolver: (s: string) => s,
			logger,
		},
	});
	handles.push(handle);
	const config = handle.components.config;
	if (config === undefined) throw new Error("createApp booted without the parsed configuration");
	return { logger, config };
}

describe("over the Store's HTTP user repository", () => {
	it("boots without REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL, warning once that the witness is unwritable", async () => {
		const { logger } = await bootShipped({ ...SHIPPED_ENV, ...MAIL_ENV }, "production");
		expect(warned(logger, "mfa_enrollment_witness_unwritable")).toHaveLength(1);
	});

	it("boots with it, and writes the witness: no such warning", async () => {
		const { logger } = await bootShipped(
			{
				...SHIPPED_ENV,
				...MAIL_ENV,
				REPOSITORIES_USER_HTTP_MARK_MFA_ENROLLED_URL: "https://store.auth.test/mfa/enrolled",
			},
			"production",
		);
		expect(warned(logger, "mfa_enrollment_witness_unwritable")).toEqual([]);
	});
});

describe("under CONFIG_ENV=development", () => {
	it("boots on the sample key config/development.conf carries, with the development mail sender, warning once", async () => {
		const { logger } = await bootShipped(SHIPPED_ENV, "development");
		expect(warned(logger, "mfa_development_sample_key_in_use")).toHaveLength(1);
	});

	it("keeps the sample key under MFA_ENCRYPTION_KEY: the development file's own ring wins over the variable", async () => {
		const { logger } = await bootShipped(
			{ ...SHIPPED_ENV, MFA_ENCRYPTION_KEY: MFA_KEY },
			"development",
		);
		expect(warned(logger, "mfa_development_sample_key_in_use")).toHaveLength(1);
	});

	it("hands boot no mfa section with MFA_MODE unset, though development.conf writes one", async () => {
		const { logger, config } = await bootShipped(
			{ ...SHIPPED_ENV, MFA_MODE: "off" },
			"development",
		);
		expect(config).not.toHaveProperty("mfa");
		expect(warned(logger, "config_sections_ignored")).toEqual([]);
	});
});
