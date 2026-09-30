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
 * Every workspace package booted together on one replica, every store in
 * memory: the standalone template's composition with the eight packages it
 * does not depend on added to it (`full-set.fixture.mts`), held to the
 * contracts that only exist when all of them meet — the added modules' boot,
 * discovery and each added feature's switch, their flows, their body limits
 * in both mount orders (with `Content-Length` and chunked), and one outage
 * per added store under the outage rule (`describeOutages`, from the
 * template's fixture).
 *
 * The template's own suite (`all-modules-composition.test.mts`) pins its
 * composition; this file re-checks a template contract only where the added
 * modules can change the answer: the token endpoint's body rule, with two
 * more routers beneath `/oauth`, and the logger every module that answers a
 * request must receive. `full-set.redis.test.mts` boots the same set on real
 * Redis under `deployment.mode = "multi"`.
 *
 * The MFA package is installed as a deployment installs it (`mfaModules` over
 * the MFA stores, `mfa.mode = "optional"`, a key of the deployment's own), so
 * the `mfa` requirement registers beside the fixture's two (ADR
 * 2026-09-28-session-admission). The step-up flows they could start are the
 * consumers' and the MFA package's suites, not this one.
 *
 * `it.fails` marks a contract the full set breaks today; its entry names the
 * defect, and the fix that mends it turns the case red. An outage case pins
 * only the part of the rule that is broken, and asserts the rest.
 */

import { createHash, generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	BootError,
	type MfaFactorStore,
	type MfaTransactionStore,
	passwordSessionAuthentication,
	type SubjectSessionIndex,
	type UserSessionStore,
	type WebAuthnCredentialStore,
} from "@o3co/auth-provider-core";
import { unreadableModuleLeaves } from "@o3co/auth-provider-core/testing";
import { DEVICE_CODE_GRANT_TYPE, deviceGrantModule } from "@o3co/auth-provider-device-grant";
import {
	ACCESS_TOKEN_TYPE,
	TOKEN_EXCHANGE_GRANT_TYPE,
} from "@o3co/auth-provider-oauth-token-exchange";
import {
	ALICE,
	AS_LISTED,
	authorize,
	basic,
	codeFrom,
	composedModules,
	contributionNames,
	cookiesOf,
	DISCOVERY_PATHS,
	describeOutages,
	expectValidMetadata,
	FORM_TYPE,
	federatedCallback,
	ISSUER,
	JSON_TYPE,
	KIB,
	type ModuleOrder,
	MULTI_ENV,
	type OutageCase,
	ownFiles,
	padForm,
	padJson,
	REVERSED,
	redeem,
	resolveConfig,
	SINGLE_ENV,
	TEMPLATE_DEPENDENCIES,
	TOO_LARGE,
	TRANSFERS,
	WEB,
	webTokens,
} from "@o3co/auth-provider-standalone/src/__tests__/all-modules-composition.fixture.mts";
import { readOwnLayers, readSwitches } from "@o3co/auth-provider-standalone/src/configPath.mts";
import { WEBAUTHN_GRANT_TYPE } from "@o3co/auth-provider-webauthn";
import type { Express } from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
	APPLE_LANDING,
	BINDER,
	CLIENT_CERTIFICATE,
	composeFullSet,
	DPOP_JWK,
	dpopProof,
	FIXTURE_COMPLETION,
	FIXTURE_INTERRUPTION,
	FIXTURE_REQUIREMENTS,
	type FixtureCeremony,
	type FullSet,
	type FullSetOptions,
	fullSetOptions,
	GATEWAY,
	GITHUB_LANDING,
	REQUIRED_BINDER,
	TV,
} from "./full-set.fixture.mts";

let current: FullSet | undefined;

afterEach(async () => {
	await current?.handle.dispose();
	current = undefined;
});

/** The `mfa` section a configuration carries: the MFA module's, which core's type does not name. */
const mfaOf = (config: unknown): Record<string, unknown> | undefined =>
	(config as { mfa?: Record<string, unknown> }).mfa;

/** Boots and remembers the full set, so `afterEach` disposes it. */
async function boot(options: FullSetOptions = {}): Promise<FullSet> {
	current = await composeFullSet(options);
	return current;
}

// ---------------------------------------------------------------------------
// What is composed
// ---------------------------------------------------------------------------

const manifest = JSON.parse(
	readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
) as { devDependencies: Record<string, string> };

/**
 * What the full set takes from each workspace package the template does not
 * compose. The template's own packages are pinned by its suite.
 */
const ADDED: Readonly<Record<string, readonly string[]>> = {
	"@o3co/auth-provider-device-grant": ["device-grant", "core-device-code-store-memory"],
	"@o3co/auth-provider-dpop": ["dpop"],
	"@o3co/auth-provider-federation-apple": ["federation-apple"],
	"@o3co/auth-provider-federation-github": ["federation-github"],
	// mfaModules, over core's memory MFA stores.
	"@o3co/auth-provider-mfa": [
		"mfa-totp-factor",
		"mfa",
		"core-mfa-factor-store-memory",
		"core-mfa-transaction-store-memory",
	],
	"@o3co/auth-provider-mtls": ["mtls"],
	"@o3co/auth-provider-oauth-token-exchange": ["oauth-token-exchange"],
	// No module: contract suites and fakes, for tests.
	"@o3co/auth-provider-test-kit": [],
	"@o3co/auth-provider-webauthn": [
		"webauthn",
		"webauthn-session-subject",
		"core-webauthn-credential-store-memory",
		"core-challenge-store-memory",
		"core-default-challenge-ceremony",
	],
};

/** The modules a deployment writes itself, beside the packages' (see the fixture). */
const DEPLOYMENT_MODULES = [
	"deployment:webauthn-config",
	"deployment:grant-policy",
	"deployment:apple-federation-config",
	"deployment:github-federation-config",
	"deployment:requirement-page",
	"deployment:requirement-bare",
];

describe("what the full set covers", () => {
	it("depends on every workspace package, so each can be booted here", () => {
		const packagesDir = new URL("../../../../packages/", import.meta.url);
		const workspace = readdirSync(packagesDir, { withFileTypes: true })
			.filter((entry) => entry.isDirectory())
			.map(
				(entry) =>
					(
						JSON.parse(
							readFileSync(new URL(`${entry.name}/package.json`, packagesDir), "utf8"),
						) as {
							name: string;
						}
					).name,
			)
			.sort();
		const depended = Object.keys(manifest.devDependencies)
			.filter((name) => name.startsWith("@o3co/auth-provider-"))
			.filter((name) => name !== "@o3co/auth-provider-standalone")
			.sort();
		expect(workspace.length).toBeGreaterThan(0);
		expect(depended).toEqual(workspace);
		// What this suite adds is exactly what the template does not compose.
		expect(Object.keys(ADDED).sort()).toEqual(
			workspace.filter((name) => !TEMPLATE_DEPENDENCIES.includes(name)),
		);
	});

	it("adds every package the template does not compose, and nothing the template already does", async () => {
		const { modules } = await boot();
		const names = modules.map((m) => m.name);
		const added = [...Object.values(ADDED).flat(), ...DEPLOYMENT_MODULES];
		for (const name of added) expect(names, name).toContain(name);
		expect(new Set(names).size, "a module listed twice").toBe(names.length);
		// The template's list, then the added modules: nothing between.
		expect(names.slice(names.length - added.length).sort()).toEqual([...added].sort());
	});
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

const ADDED_GRANTS = [DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE, WEBAUTHN_GRANT_TYPE];
const ALL_GRANTS = [
	"authorization_code",
	"client_credentials",
	"refresh_token",
	"session",
	...ADDED_GRANTS,
].sort();

describe("the full set boots together", () => {
	it("mounts every added route, registers every federation and every grant", async () => {
		const { handle, app } = await boot();
		const ids = handle.routes.map((r) => r.contribution.id);
		for (const id of [
			"device-authorization",
			"device-verification",
			"webauthn-registration-options",
			"webauthn-registration-verify",
			"webauthn-authentication-options",
		]) {
			expect(ids, id).toContain(id);
		}
		expect([...(handle.components.federationProviders?.keys() ?? [])].sort()).toEqual([
			"apple",
			"github",
			"google",
			"oidc",
		]);
		const discovery = await request(app).get(DISCOVERY_PATHS[0]);
		expect([...discovery.body.grant_types_supported].sort()).toEqual(ALL_GRANTS);
	});

	it("installs the MFA package: the TOTP factor from its reference.conf, and the requirement named mfa under mfa.mode = optional, reaching what the factor reaches", async () => {
		const { handle, config } = await boot();
		expect(handle.components.mfaFactorResolver?.get("totp")?.amrValues).toEqual(["otp"]);
		expect(
			[...(handle.components.sessionRequirementResolver?.entries() ?? [])]
				.map(([name]) => name)
				.sort(),
		).toEqual([...FIXTURE_REQUIREMENTS, "mfa"].sort());
		expect(
			[...(handle.components.sessionRequirementResolver?.get("mfa")?.reach ?? [])].sort(),
		).toEqual(["mfa", "otp"]);
		expect((config as unknown as { mfa: { mode: unknown } }).mfa.mode).toBe("optional");
	});

	it("hands the deployment's logger to every added module that answers a request or binds a token", async () => {
		const { modules } = await boot();
		const addedNames = new Set(Object.values(ADDED).flat());
		const answering = modules.filter(
			(m) =>
				addedNames.has(m.name) &&
				contributionNames(m, "routes").length +
					contributionNames(m, "grants").length +
					contributionNames(m, "tokenBindingMechanisms").length >
					0,
		);
		expect(answering.map((m) => m.name).sort()).toEqual(
			[
				"device-grant",
				"dpop",
				"mfa",
				"mtls",
				"oauth-token-exchange",
				"webauthn",
				"webauthn-session-subject",
			].sort(),
		);
		for (const module of answering) {
			expect([...(module.requires ?? []), ...(module.optional ?? [])], module.name).toContain(
				"logger",
			);
		}
	});
});

// ---------------------------------------------------------------------------
// The configuration
// ---------------------------------------------------------------------------

const isObject = (value: unknown): value is Record<string, unknown> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/** Every dotted path in `tree` that carries a value; a list is one value. */
function leafPaths(tree: unknown, prefix = ""): string[] {
	if (!isObject(tree) || Object.keys(tree).length === 0) return prefix === "" ? [] : [prefix];
	return Object.entries(tree).flatMap(([key, value]) =>
		leafPaths(value, prefix === "" ? key : `${prefix}.${key}`),
	);
}

/** The value at a dotted path, or `undefined`. */
function valueAt(tree: unknown, path: string): unknown {
	let cursor: unknown = tree;
	for (const key of path.split(".")) {
		if (!isObject(cursor) || !Object.hasOwn(cursor, key)) return undefined;
		cursor = cursor[key];
	}
	return cursor;
}

describe("the configuration createApp is handed reaches every loaded module whole", () => {
	it("layers each added package's reference.conf, because its modules declare it", async () => {
		const { resolved } = await boot();
		// A default each package ships and no layer above it sets.
		for (const path of [
			"oauth.deviceAuthorization.rateLimit.windowSeconds",
			"oauth.dpop.iat-window-seconds",
			"oauth.mtls.full-pki.max-chain-depth",
			"webauthn.rateLimit.authenticationOptions.limit",
			"mfa-totp-factor.enabled",
		]) {
			expect(valueAt(resolved, path), path).toBeDefined();
		}
	});

	it("strips no path of what createApp was handed but the captures of renamed variables, which boot judges and removes", async () => {
		const { resolved, config } = await boot();
		const paths = leafPaths(resolved);
		expect(paths.length).toBeGreaterThan(150);
		const captures = (path: string) => path.startsWith("renamed-variables.");
		expect(paths.filter(captures).length).toBeGreaterThan(0);
		expect(valueAt(config, "renamed-variables")).toBeUndefined();
		expect(paths.filter((path) => !captures(path) && valueAt(config, path) === undefined)).toEqual(
			[],
		);
	});

	it("keeps each added package's switch as the deployment wrote it", async () => {
		const { config } = await boot();
		const on = config as unknown as Record<string, unknown>;
		expect(valueAt(on, "oauth.deviceAuthorization.enabled")).toBe(true);
		expect(valueAt(on, "oauth.dpop.enabled")).toBe(true);
		expect(valueAt(on, "oauth.mtls.enabled")).toBe(true);
		expect(valueAt(on, "oauth.mtls.trusted-proxies")).toEqual(["loopback"]);
		expect(valueAt(on, "webauthn.rpId")).toBe("auth.test");
	});

	it("reads the device grant's switch in phase one as the operator wrote it, so the grant registers", () => {
		// A deployment that adds the device grant to the template's modules
		// reads its switch before boot too: `deviceGrantModule({ config })`
		// decides from it whether the grant exists.
		const operator = join(mkdtempSync(join(tmpdir(), "full-set-472-")), "device.conf");
		writeFileSync(
			operator,
			`oauth.deviceAuthorization {\n  enabled = \${?DEVICE_GRANT_ENABLED}\n  verification-uri = "${ISSUER}/device"\n}\n`,
		);
		const reads = ["oauth.deviceAuthorization.enabled"];
		const switches = readSwitches(
			readOwnLayers([operator, ...ownFiles()], {
				env: { ...SINGLE_ENV, DEVICE_GRANT_ENABLED: "true" },
			}),
			{ reads },
		);
		expect(contributionNames(deviceGrantModule({ config: switches }), "grants")).toEqual([
			DEVICE_CODE_GRANT_TYPE,
		]);
		// And off where nothing says on: the grant is opt-in.
		const unset = readSwitches(readOwnLayers([operator, ...ownFiles()], { env: SINGLE_ENV }), {
			reads,
		});
		expect(contributionNames(deviceGrantModule({ config: unset }), "grants")).toEqual([]);
	});

	it("reads every leaf a module declares from the string an environment variable carries, every store on Redis", async () => {
		// Boot's parse is plain Zod: a bare boolean or number a module reads,
		// with core's base not coercing the path first, would refuse `"false"`.
		const options = await fullSetOptions({ stores: "redis" });
		const switches = resolveConfig(MULTI_ENV, options.reads);
		const modules = composedModules(options.config ? options.config(switches) : switches, {
			...options,
			env: MULTI_ENV,
			shippedRefreshTokenFamilyStore: true,
		});
		expect(modules.length).toBeGreaterThan(40);
		expect(unreadableModuleLeaves(modules)).toEqual([]);
	});

	it("names no section as ignored: every one it is handed has an owner", async () => {
		const { logger } = await boot();
		expect(
			logger.lines.filter((line) => JSON.stringify(line).includes("config_sections_ignored")),
		).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// A path a section moved from, through the template's own reading
// ---------------------------------------------------------------------------

describe("a setting still written where its section moved from, read as the template reads its configuration", () => {
	it("refuses the boot when the operator's own layer writes the TOTP factor's old path, naming the new one and its variable", async () => {
		const err = await refused({ operatorHocon: "mfa.factors.totp { enabled = false }\n" });
		expect(err.reason).toBe("config-path-relocated");
		expect(err.details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "mfa-totp-factor",
					from: "mfa.factors.totp.enabled",
					to: "mfa-totp-factor.enabled",
					environmentVariable: "MFA_TOTP_FACTOR_ENABLED",
				},
			],
		});
	});

	it("refuses the boot when the environment sets a TOTP variable renamed with the move, and not its new name", async () => {
		const err = await refused({ env: { ...SINGLE_ENV, MFA_TOTP_ISSUER: "Example Co" } });
		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toEqual({
			reason: "environment-variable-renamed",
			renamed: [
				{
					module: "mfa-totp-factor",
					from: "MFA_TOTP_ISSUER",
					to: "MFA_TOTP_FACTOR_ISSUER",
					path: "mfa-totp-factor.issuer",
					state: "unset",
				},
			],
		});
	});

	it("refuses the boot when a renamed TOTP variable and its new name are set to different values", async () => {
		const err = await refused({
			env: { ...SINGLE_ENV, MFA_TOTP_ENABLED: "false", MFA_TOTP_FACTOR_ENABLED: "true" },
		});
		expect(err.reason).toBe("environment-variable-renamed");
		expect(err.details).toMatchObject({
			renamed: [{ from: "MFA_TOTP_ENABLED", to: "MFA_TOTP_FACTOR_ENABLED", state: "different" }],
		});
	});

	it("boots with a renamed TOTP variable and its new name set to the same value, and the factor reads it", async () => {
		const { handle } = await boot({
			env: { ...SINGLE_ENV, MFA_TOTP_ENABLED: "false", MFA_TOTP_FACTOR_ENABLED: "false" },
		});
		expect(handle.components.mfaFactorResolver?.get("totp")).toBeUndefined();
	});

	it("boots with the setting at the new path, through its variable, and the factor reads it", async () => {
		const { handle } = await boot({ env: { ...SINGLE_ENV, MFA_TOTP_FACTOR_ENABLED: "false" } });
		expect(handle.components.mfaFactorResolver?.get("totp")).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// Session requirements (ADR 2026-09-28-session-admission)
// ---------------------------------------------------------------------------

/** Boots the full set expecting the planner to refuse it, and hands back the refusal. */
async function refused(options: FullSetOptions): Promise<BootError> {
	try {
		current = await composeFullSet(options);
	} catch (err) {
		if (err instanceof BootError) return err;
		throw err;
	}
	throw new Error("the full set booted");
}

/** The requirements the full set registers: the MFA package's and the two a deployment writes. */
const REGISTERED = ["mfa", ...FIXTURE_REQUIREMENTS];

describe("the session requirements: the MFA package's, and the two a deployment writes", () => {
	it("are said at boot, once: each registered requirement with its module, its remediations and whether it declares the second-factor authority, in registration order", async () => {
		const { logger } = await boot();
		const said = logger.lines.filter((line) => line.args[1] === "session_requirements_registered");
		expect(said).toHaveLength(1);
		expect(said[0]?.level).toBe("info");
		const { requirements } = (said[0]?.args[0] ?? { requirements: [] }) as {
			requirements: {
				name: string;
				module: string;
				remediations: string[];
				secondFactorAuthority: boolean;
			}[];
		};
		expect([...requirements].sort((a, b) => a.name.localeCompare(b.name))).toEqual([
			{
				name: "fixture-bare",
				module: "deployment:requirement-bare",
				remediations: [],
				secondFactorAuthority: false,
			},
			{
				name: "fixture-page",
				module: "deployment:requirement-page",
				remediations: ["fixture-page.step_up"],
				secondFactorAuthority: false,
			},
			{ name: "mfa", module: "mfa", remediations: ["mfa.step_up"], secondFactorAuthority: true },
		]);
		// The fixtures in the order the deployment listed them.
		expect(requirements.map((r) => r.name).filter((name) => name !== "mfa")).toEqual(
			FIXTURE_REQUIREMENTS,
		);
	});

	it("are declared: the composition's sessionRequirements.expected names exactly them — mfa, as a deployment that installs the MFA package declares it, and the deployment's own", async () => {
		const { config } = await boot();
		expect([...(config.sessionRequirements?.expected ?? [])].sort()).toEqual(
			[...REGISTERED].sort(),
		);
	});

	it("refuse the boot when the declaration is the template's own — nothing expected — naming what registered and who consults admission", async () => {
		const err = await refused({
			adjust: (config) => ({ ...config, sessionRequirements: { expected: [] } }),
		});
		expect(err.reason).toBe("session-requirements-undeclared");
		expect(err.details).toMatchObject({
			configKey: "sessionRequirements.expected",
			declared: [],
			registered: expect.arrayContaining(REGISTERED),
			consumedBy: expect.arrayContaining(["oauth", "mfa"]),
		});
	});

	it("refuse the boot when a name is declared that nothing registers: session-requirement-missing, naming it", async () => {
		const err = await refused({
			adjust: (config) => ({
				...config,
				sessionRequirements: { expected: [...REGISTERED, "risk"] },
			}),
		});
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			configKey: "sessionRequirements.expected",
			missing: ["risk"],
			declared: [...REGISTERED, "risk"],
			registered: expect.arrayContaining(REGISTERED),
		});
	});

	it('refuse the boot under mfa.mode = "off" with the MFA module installed: remove the module, or set mfa.mode', async () => {
		const err = await refused({
			adjust: (config) => ({ ...config, mfa: { ...mfaOf(config), mode: "off" } }),
		});
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({ module: "mfa", kind: "sessionRequirements" });
	});

	it("refuse the boot when mfa is declared and the MFA package is not installed: session-requirement-missing, naming the key and mfa", async () => {
		const err = await refused({
			features: { mfa: false },
			adjust: (config) => ({
				...config,
				sessionRequirements: { expected: [...(config.sessionRequirements?.expected ?? []), "mfa"] },
			}),
		});
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			configKey: "sessionRequirements.expected",
			missing: ["mfa"],
			registered: [...FIXTURE_REQUIREMENTS],
		});
	});

	it("refuse the boot under mfa.mode = required without the MFA package: the template declares mfa from the mode, and nothing registers it", async () => {
		const err = await refused({
			features: { mfa: false },
			adjust: (config) => ({ ...config, mfa: { ...mfaOf(config), mode: "required" } }),
		});
		expect(err.reason).toBe("session-requirement-missing");
		expect(err.details).toMatchObject({
			configKey: "sessionRequirements.expected",
			missing: ["mfa"],
			registered: [...FIXTURE_REQUIREMENTS],
		});
	});
});

describe("a password login both requirements interrupt, resumed through each", () => {
	it("is interrupted by the first, resumed into the second with the first's completion done, and established once — as a password login, through the exported establishSession", async () => {
		const ceremonies: FixtureCeremony[] = [];
		const { app, handle, config } = await boot({ interruptLogins: [ALICE.sub], ceremonies });
		const { userSessionStore, subjectSessionIndex } = handle.components as unknown as {
			userSessionStore: UserSessionStore;
			subjectSessionIndex: SubjectSessionIndex;
		};
		const create = vi.spyOn(userSessionStore, "create");

		// The password login: the first requirement interrupts; nothing is written.
		const csrf = await request(app).get("/session/csrf");
		const login = await request(app)
			.post("/session/login")
			.set("Cookie", cookiesOf(csrf))
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(login.status).toBe(403);
		expect(login.body).toEqual(FIXTURE_INTERRUPTION.page.body);
		expect(ceremonies.map((c) => c.requirement)).toEqual(["fixture-page"]);
		const [atLogin] = ceremonies;
		expect(atLogin?.continuation).toMatchObject({
			interruptedBy: "fixture-page",
			done: [],
			primary: { subject: ALICE.sub, recorded: { amr: ["pwd"] } },
		});
		expect(create).not.toHaveBeenCalled();

		// The first requirement's completion resumes the login; the second
		// interrupts it, the first's completion carried in `done`.
		const first = await request(app)
			.post(`${FIXTURE_COMPLETION.page}/complete`)
			.set("Cookie", cookiesOf(login));
		expect(first.status).toBe(403);
		expect(first.body).toEqual(FIXTURE_INTERRUPTION.bare.body);
		// Answered as the login answers an interruption (the session package's
		// answerInterruption): a fresh CSRF token beside the 403.
		expect(cookiesOf(first).some((c) => c.startsWith(`${config.session.name}.csrf=`))).toBe(true);
		expect(ceremonies.map((c) => c.requirement)).toEqual(["fixture-page", "fixture-bare"]);
		const atFirst = ceremonies[1];
		expect(atFirst?.continuation).toMatchObject({
			interruptedBy: "fixture-bare",
			done: [{ requirement: "fixture-page", adds: { amr: [] } }],
		});
		expect(atFirst?.continuation.primary).toEqual(atLogin?.continuation.primary);
		// Each ceremony is bound to the session the interrupting route regenerated.
		expect(atFirst?.sessionId).not.toBe(atLogin?.sessionId);
		expect(create).not.toHaveBeenCalled();

		// The second's completion resumes it with both done: established.
		const second = await request(app)
			.post(`${FIXTURE_COMPLETION.bare}/complete`)
			.set("Cookie", cookiesOf(first));
		expect(second.status).toBe(200);
		expect(ceremonies).toHaveLength(2);

		// Written once, as a password login's primary composes it: `pwd`, no
		// second factor — neither fixture adds anything, and neither is `mfa`.
		expect(create).toHaveBeenCalledTimes(1);
		const sids = await subjectSessionIndex.listSids(ALICE.sub);
		expect(sids).toHaveLength(1);
		const record = await userSessionStore.get(sids[0] as string);
		expect({ amr: record?.amr, authentication: record?.authentication }).toEqual(
			passwordSessionAuthentication(),
		);
		expect(record?.authTime.getTime()).toBe(atLogin?.continuation.primary.authTimeMs);

		// The session the last completion established is the browser's.
		const authorized = await authorize(app, cookiesOf(second));
		expect(authorized.headers.location).toMatch(/\?code=/);
	});

	it("refuses a completion on a session no ceremony is bound to, and a ceremony presented twice on the live session it is bound to — spent even when its resumption failed", async () => {
		const { app } = await boot({ interruptLogins: [ALICE.sub], failAskOnce: "fixture-bare" });
		const csrf = await request(app).get("/session/csrf");
		const login = await request(app)
			.post("/session/login")
			.set("Cookie", cookiesOf(csrf))
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(login.status).toBe(403);
		const bare = await request(app)
			.post(`${FIXTURE_COMPLETION.bare}/complete`)
			.set("Cookie", cookiesOf(login));
		expect(bare.status).toBe(400);
		// The first requirement's completion: the resumption meets the second
		// requirement's outage, so nothing is regenerated and the session the
		// ceremony is bound to stays live.
		const first = await request(app)
			.post(`${FIXTURE_COMPLETION.page}/complete`)
			.set("Cookie", cookiesOf(login));
		expect(first.status).toBe(503);
		// Presented again on that live session, with the outage over: spent.
		const again = await request(app)
			.post(`${FIXTURE_COMPLETION.page}/complete`)
			.set("Cookie", cookiesOf(login));
		expect(again.status).toBe(400);
	});
});

describe("a password login the mfa requirement interrupts, through the template's boot", () => {
	it("answers a subject who holds a factor 403 mfa_required with the closed body, a transaction bound to the regenerated session, and no UserSession written", async () => {
		const { app, handle, config } = await boot();
		const { mfaFactorStore, mfaTransactionStore, userSessionStore } =
			handle.components as unknown as {
				mfaFactorStore: MfaFactorStore;
				mfaTransactionStore: MfaTransactionStore;
				userSessionStore: UserSessionStore;
			};
		await mfaFactorStore.create({
			id: "f-alice",
			subject: ALICE.sub,
			kind: "totp",
			label: undefined,
			binding: "password",
			createdAt: new Date(),
			lastUsedAt: undefined,
			version: 0,
			data: "sealed",
		});
		const create = vi.spyOn(userSessionStore, "create");
		const csrf = await request(app).get("/session/csrf");
		const login = await request(app)
			.post("/session/login")
			.set("Cookie", cookiesOf(csrf))
			.set(csrf.body.header_name as string, csrf.body.csrf_token as string)
			.type("form")
			.send({ username: ALICE.username, password: ALICE.password });
		expect(login.status).toBe(403);
		expect(login.body).toEqual({
			error: "mfa_required",
			transaction: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
			expires_in: 600,
		});
		const transaction = await mfaTransactionStore.get(login.body.transaction as string);
		// The session the browser now holds: express-session signs it `s:<id>.<signature>`.
		const cookie = cookiesOf(login).find((c) => c.startsWith(`${config.session.name}=`));
		const signed = decodeURIComponent((cookie ?? "").split(";")[0]?.split("=")[1] ?? "");
		expect(signed.startsWith("s:")).toBe(true);
		expect(transaction).toMatchObject({
			purpose: "login",
			binding: { kind: "session", id: signed.slice(2, signed.lastIndexOf(".")) },
			subject: ALICE.sub,
			continuation: { interruptedBy: "mfa", primary: { subject: ALICE.sub } },
		});
		expect(create).not.toHaveBeenCalled();
	});
});

/** A confidential client that signs users in with a passkey and keeps them signed in with refresh tokens. */
const PASSKEY_APP = { id: "passkey-app", secret: "passkey-app-secret" } as const;

const b64url = (bytes: Buffer | Uint8Array): string => Buffer.from(bytes).toString("base64url");

/**
 * A software passkey: a P-256 key whose public half is registered for
 * `userId` as the WebAuthn package stores it (COSE), and an assertion over
 * a challenge the provider issued, signed as an authenticator signs one —
 * authenticator data (the RP id's hash, user present and verified, a
 * counter) and the client data's hash, ECDSA over SHA-256, DER.
 */
function softwarePasskey(rpId: string, origin: string) {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const jwk = publicKey.export({ format: "jwk" });
	const x = Buffer.from(jwk.x as string, "base64url");
	const y = Buffer.from(jwk.y as string, "base64url");
	// COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}, CBOR.
	const cose = Buffer.concat([
		Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
		x,
		Buffer.from([0x22, 0x58, 0x20]),
		y,
	]);
	const credentialId = b64url(createHash("sha256").update(cose).digest().subarray(0, 16));
	let counter = 0;
	return {
		credentialId,
		publicKey: new Uint8Array(cose),
		assert(challenge: string) {
			counter += 1;
			const clientDataJSON = Buffer.from(
				JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }),
			);
			const count = Buffer.alloc(4);
			count.writeUInt32BE(counter);
			const authenticatorData = Buffer.concat([
				createHash("sha256").update(rpId).digest(),
				Buffer.from([0x05]),
				count,
			]);
			const signature = sign(
				"sha256",
				Buffer.concat([authenticatorData, createHash("sha256").update(clientDataJSON).digest()]),
				privateKey,
			);
			return {
				id: credentialId,
				rawId: credentialId,
				type: "public-key",
				response: {
					clientDataJSON: b64url(clientDataJSON),
					authenticatorData: b64url(authenticatorData),
					signature: b64url(signature),
				},
				clientExtensionResults: {},
			};
		},
	};
}

describe("a passkey sign-in under mfa.mode = required", () => {
	it("is kept by its refresh token: the WebAuthn grant's hwk is a second-factor value, so the refresh is met without a sid or a primary's marker", async () => {
		const { app, handle } = await boot({
			adjust: (config) => ({ ...config, mfa: { ...mfaOf(config), mode: "required" } }),
			extraClients: {
				[PASSKEY_APP.id]: {
					tokenEndpointAuthMethod: "client_secret_basic",
					clientSecret: PASSKEY_APP.secret,
					allowedScopes: ["openid"],
					defaultScopes: ["openid"],
					allowedGrantTypes: [WEBAUTHN_GRANT_TYPE, "refresh_token"],
				},
			},
		});
		const { webauthnCredentialStore } = handle.components as unknown as {
			webauthnCredentialStore: WebAuthnCredentialStore;
		};
		const passkey = softwarePasskey("auth.test", ISSUER);
		await webauthnCredentialStore.registerCredential({
			userId: ALICE.sub,
			credentialId: passkey.credentialId,
			publicKey: passkey.publicKey,
			signCount: 0,
			backedUp: false,
			createdAt: new Date(),
		});
		const options = await request(app).post("/oauth/webauthn/authentication/options").send({});
		expect(options.status).toBe(200);
		const signedIn = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(PASSKEY_APP))
			.send({
				grant_type: WEBAUTHN_GRANT_TYPE,
				assertion: passkey.assert(options.body.challenge as string),
			});
		expect(signedIn.status, JSON.stringify(signedIn.body)).toBe(200);
		expect(typeof signedIn.body.refresh_token).toBe("string");

		const refreshed = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(PASSKEY_APP))
			.type("form")
			.send({ grant_type: "refresh_token", refresh_token: signedIn.body.refresh_token });
		expect(refreshed.status, JSON.stringify(refreshed.body)).toBe(200);
		expect(typeof refreshed.body.access_token).toBe("string");
	});
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

describe("discovery with every package on", () => {
	it.each(DISCOVERY_PATHS)(
		"%s is valid and advertises what the added modules contribute",
		async (path) => {
			const { app } = await boot();
			const res = await request(app).get(path);
			expect(res.status).toBe(200);
			expectValidMetadata(res.body);
			expect([...res.body.grant_types_supported].sort()).toEqual(ALL_GRANTS);
			expect(res.body.device_authorization_endpoint).toBe(`${ISSUER}/oauth/device_authorization`);
			expect(res.body.dpop_signing_alg_values_supported).toEqual([
				"ES256",
				"ES384",
				"EdDSA",
				"RS256",
			]);
			expect(res.body.tls_client_certificate_bound_access_tokens).toBe(true);
		},
	);

	it("answers the device authorization endpoint it advertises", async () => {
		const { app } = await boot();
		const { pathname } = new URL(
			(await request(app).get(DISCOVERY_PATHS[0])).body.device_authorization_endpoint as string,
		);
		expect((await request(app).post(pathname).type("form").send({})).status).not.toBe(404);
	});

	/**
	 * Each added feature off, alone: exactly what it contributed leaves the
	 * document, and its route (where it has one) stops answering.
	 */
	const TOGGLES: ReadonlyArray<
		readonly [
			feature: keyof NonNullable<FullSetOptions["features"]>,
			gone: { grant?: string; fields?: readonly string[]; route?: readonly [string, string] },
		]
	> = [
		[
			"deviceGrant",
			{
				grant: DEVICE_CODE_GRANT_TYPE,
				fields: ["device_authorization_endpoint"],
				route: ["post", "/oauth/device_authorization"],
			},
		],
		["dpop", { fields: ["dpop_signing_alg_values_supported"] }],
		["mtls", { fields: ["tls_client_certificate_bound_access_tokens"] }],
		["tokenExchange", { grant: TOKEN_EXCHANGE_GRANT_TYPE }],
		[
			"webauthn",
			{ grant: WEBAUTHN_GRANT_TYPE, route: ["post", "/oauth/webauthn/authentication/options"] },
		],
		["apple", { route: ["get", "/session/oauth/federation/apple"] }],
		["github", { route: ["get", "/session/oauth/federation/github"] }],
		// MFA contributes nothing to discovery: its reach meets no acr entry the template ships.
		["mfa", {}],
	];

	it.each(TOGGLES)(
		"%s off: only what it contributed leaves the document and the app",
		async (feature, gone) => {
			const on = await boot();
			const before = (await request(on.app).get(DISCOVERY_PATHS[0])).body as Record<
				string,
				unknown
			>;
			await on.handle.dispose();
			current = undefined;

			const { app } = await boot({ features: { [feature]: false } });
			const after = (await request(app).get(DISCOVERY_PATHS[0])).body as Record<string, unknown>;
			expectValidMetadata(after);
			const expected: Record<string, unknown> = { ...before };
			for (const field of gone.fields ?? []) delete expected[field];
			expected.grant_types_supported = (before.grant_types_supported as string[]).filter(
				(g) => g !== gone.grant,
			);
			expect(after).toEqual(expected);
			if (gone.route !== undefined) {
				const [method, path] = gone.route;
				const res = await request(app)[method as "get" | "post"](path).send({});
				expect(res.status, path).toBe(404);
			}
		},
	);
});

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Sign in through the session routes on one cookie jar, and hand back the jar and a CSRF pair. */
async function signedIn(app: Express) {
	const agent = request.agent(app);
	const first = await agent.get("/session/csrf");
	const login = await agent
		.post("/session/login")
		.set(first.body.header_name as string, first.body.csrf_token as string)
		.type("form")
		.send({ username: ALICE.username, password: ALICE.password });
	expect(login.status).toBe(200);
	const csrf = await agent.get("/session/csrf");
	return {
		agent,
		header: csrf.body.header_name as string,
		token: csrf.body.csrf_token as string,
	};
}

const tokenPayload = (token: string): Record<string, unknown> =>
	JSON.parse(Buffer.from(token.split(".")[1] as string, "base64url").toString()) as Record<
		string,
		unknown
	>;

/** RFC 7638 thumbprint of the fixture's DPoP key. */
const DPOP_JKT = createHash("sha256")
	.update(JSON.stringify({ crv: DPOP_JWK.crv, kty: DPOP_JWK.kty, x: DPOP_JWK.x, y: DPOP_JWK.y }))
	.digest("base64url");

describe("every added module's primary route answers in the one app", () => {
	it("the device grant: authorization, the user's approval, the poll", async () => {
		const { app } = await boot();
		const started = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		expect(started.status).toBe(200);
		expect(started.body.verification_uri).toBe(`${ISSUER}/device`);
		// One poll, after the approval: a second inside the five-second interval
		// is RFC 8628's `slow_down`, which is the grant working, not the flow.
		const poll = () =>
			request(app).post("/oauth/token").type("form").send({
				grant_type: DEVICE_CODE_GRANT_TYPE,
				client_id: TV.id,
				device_code: started.body.device_code,
			});

		const { agent, header, token } = await signedIn(app);
		const approved = await agent
			.post("/oauth/device/verification")
			.set(header, token)
			.send({ action: "approve", user_code: started.body.user_code });
		expect(approved.status).toBe(200);
		expect(approved.body.status).toBe("approved");

		const tokens = await poll();
		expect(tokens.status).toBe(200);
		expect(tokenPayload(tokens.body.access_token as string)).toMatchObject({
			sub: ALICE.sub,
			azp: TV.id,
		});
	});

	it("token exchange: a gateway exchanges the web client's access token", async () => {
		const { app } = await boot();
		const { access_token } = await webTokens(app);
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(GATEWAY))
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: access_token,
				subject_token_type: ACCESS_TOKEN_TYPE,
			});
		expect(res.status).toBe(200);
		expect(res.body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(tokenPayload(res.body.access_token as string)).toMatchObject({
			sub: ALICE.sub,
			azp: GATEWAY.id,
		});
	});

	it("DPoP: a client_credentials token bound to the proof's key", async () => {
		const { app } = await boot();
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(BINDER))
			.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
			.type("form")
			.send({ grant_type: "client_credentials" });
		expect(res.status).toBe(200);
		expect(res.body.token_type).toBe("DPoP");
		expect(tokenPayload(res.body.access_token as string).cnf).toEqual({ jkt: DPOP_JKT });
	});

	it("DPoP: the device's poll with a proof gets a token bound to its key, advertised as DPoP (RFC 9449 §5)", async () => {
		// The real DPoP mechanism beside the device grant. A token bound by
		// `cnf.jkt` must be advertised as DPoP: told Bearer, a DPoP-aware device
		// presents it as a bearer token, which a resource server that enforces
		// the binding refuses (§7.1).
		const { app } = await boot();
		const started = await request(app)
			.post("/oauth/device_authorization")
			.type("form")
			.send({ client_id: TV.id });
		const { agent, header, token } = await signedIn(app);
		const approved = await agent
			.post("/oauth/device/verification")
			.set(header, token)
			.send({ action: "approve", user_code: started.body.user_code });
		expect(approved.status).toBe(200);

		const res = await request(app)
			.post("/oauth/token")
			.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
			.type("form")
			.send({
				grant_type: DEVICE_CODE_GRANT_TYPE,
				client_id: TV.id,
				device_code: started.body.device_code,
			});
		expect(res.status).toBe(200);
		expect(tokenPayload(res.body.access_token as string).cnf).toEqual({ jkt: DPOP_JKT });
		expect(res.body.token_type).toBe("DPoP");
	});

	describe("a client that requires a sender constraint, with the real mechanisms", () => {
		// The dispatch gate refuses a binding whose confirmation its mechanism
		// does not own. The real DPoP and mTLS mechanisms always hand over the
		// member they own, so neither is ever refused by it — pinned here, so
		// the gate cannot come to refuse what it exists to admit.
		it("DPoP: admitted, and the token is bound to the proof's key", async () => {
			const { app } = await boot();
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(REQUIRED_BINDER))
				.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
				.type("form")
				.send({ grant_type: "client_credentials" });
			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("DPoP");
			expect(tokenPayload(res.body.access_token as string).cnf).toEqual({ jkt: DPOP_JKT });
		});

		it("mTLS: admitted, and the token is bound to the certificate", async () => {
			const { app } = await boot();
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(REQUIRED_BINDER))
				.set("x-forwarded-client-cert", encodeURIComponent(CLIENT_CERTIFICATE))
				.type("form")
				.send({ grant_type: "client_credentials" });
			expect(res.status).toBe(200);
			expect(res.body.token_type).toBe("Bearer");
			const thumbprint = createHash("sha256")
				.update(new X509Certificate(CLIENT_CERTIFICATE).raw)
				.digest("base64url");
			expect(tokenPayload(res.body.access_token as string).cnf).toEqual({
				"x5t#S256": thumbprint,
			});
		});

		it("no binding at all: refused before any token is minted", async () => {
			const { app } = await boot();
			const res = await request(app)
				.post("/oauth/token")
				.set("Authorization", basic(REQUIRED_BINDER))
				.type("form")
				.send({ grant_type: "client_credentials" });
			expect(res.status).toBe(401);
			expect(res.body.error).toBe("invalid_client");
			expect(res.body.access_token).toBeUndefined();
		});
	});

	it("mTLS: a client_credentials token bound to the forwarded certificate", async () => {
		const { app } = await boot();
		const res = await request(app)
			.post("/oauth/token")
			.set("Authorization", basic(BINDER))
			.set("x-forwarded-client-cert", encodeURIComponent(CLIENT_CERTIFICATE))
			.type("form")
			.send({ grant_type: "client_credentials" });
		expect(res.status).toBe(200);
		const thumbprint = createHash("sha256")
			.update(new X509Certificate(CLIENT_CERTIFICATE).raw)
			.digest("base64url");
		expect(tokenPayload(res.body.access_token as string).cnf).toEqual({
			"x5t#S256": thumbprint,
		});
	});

	it("WebAuthn: authentication options for this relying party", async () => {
		const { app } = await boot();
		const res = await request(app).post("/oauth/webauthn/authentication/options").send({});
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({ rpId: "auth.test", challenge: expect.any(String) });
	});

	it("WebAuthn: registration options for the signed-in user, through the package's session-subject module", async () => {
		const { app } = await boot();
		const { agent, header, token } = await signedIn(app);
		const res = await agent
			.post("/oauth/webauthn/registration/options")
			.set(header, token)
			.send({});
		expect(res.status).toBe(200);
		expect(res.body).toMatchObject({
			rp: { id: "auth.test" },
			challenge: expect.any(String),
			excludeCredentials: [],
		});
	});

	it("Apple: a form_post login ends in a session /authorize accepts", async () => {
		const { app, fakes } = await boot();
		const start = await request(app).get("/session/oauth/federation/apple");
		expect(start.status).toBe(302);
		const answer = fakes.apple.authorize(start.headers.location as string);
		const callback = await request(app)
			.post("/session/oauth/federation/apple/callback")
			.set("Cookie", cookiesOf(start))
			.type("form")
			.send({ code: answer.code, state: answer.state ?? "" });
		expect(callback.status).toBe(302);
		expect(callback.headers.location).toBe(APPLE_LANDING);
		const authorized = await authorize(app, cookiesOf(callback));
		expect(authorized.headers.location).toMatch(/\?code=/);
	});

	it("GitHub: a login ends in a session /authorize accepts", async () => {
		const { app } = await boot();
		const start = await request(app).get("/session/oauth/federation/github");
		expect(start.status).toBe(302);
		const state = new URL(start.headers.location as string).searchParams.get("state") ?? "";
		const callback = await request(app)
			.get("/session/oauth/federation/github/callback")
			.set("Cookie", cookiesOf(start))
			.query({ code: "github-code", state });
		expect(callback.status).toBe(302);
		expect(callback.headers.location).toBe(GITHUB_LANDING);
		const authorized = await authorize(app, cookiesOf(callback));
		expect(authorized.headers.location).toMatch(/\?code=/);
	});
});

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

describe.each([AS_LISTED, REVERSED] satisfies ModuleOrder[])("bodies, modules %s", (order) => {
	let composed: FullSet;
	beforeAll(async () => {
		composed = await composeFullSet({ order });
	});
	afterAll(async () => {
		await composed.handle.dispose();
	});

	it("puts the added routers on the other side of oauthModule's, and swaps the /session pair", () => {
		const ids = composed.handle.routes.map((r) => r.contribution.id);
		for (const [own, added] of [
			["oauth-endpoints", "device-authorization"],
			["oauth-endpoints", "device-verification"],
			["oauth-endpoints", "webauthn-authentication-options"],
			["federation-grants-browser", "session-routes"],
		] as const) {
			expect(ids, own).toContain(own);
			expect(ids, added).toContain(added);
			expect(ids.indexOf(own) < ids.indexOf(added), `${own} / ${added}`).toBe(order === AS_LISTED);
		}
	});

	it.each(TRANSFERS)(
		"/oauth/device_authorization keeps its 16 KiB bound, a body sent %s",
		async (_transfer, send) => {
			for (const [type, body] of [
				[FORM_TYPE, padForm(40 * KIB, `client_id=${TV.id}`)],
				[JSON_TYPE, padJson(40 * KIB, { client_id: TV.id })],
			] as const) {
				const res = await send(composed.app, "/oauth/device_authorization", type, body);
				expect(res.status, type).toBe(413);
				expect(res.body, type).toEqual({
					error: "invalid_request",
					error_description: "body_too_large",
				});
			}
		},
	);

	it.each(TRANSFERS)(
		"/oauth/device/verification keeps its 16 KiB bound, a body sent %s",
		async (_transfer, send) => {
			const res = await send(
				composed.app,
				"/oauth/device/verification",
				JSON_TYPE,
				padJson(40 * KIB, { action: "lookup", user_code: "BCDF-GHJK" }),
			);
			expect(res.status).toBe(413);
			expect(res.body).toEqual({
				error: "invalid_request",
				error_description: "body_too_large",
			});
		},
	);

	it.each(TRANSFERS)(
		"WebAuthn authentication options parse past 16 KiB and stop at their 100 KiB, a body sent %s",
		async (_transfer, send) => {
			const path = "/oauth/webauthn/authentication/options";
			const within = await send(composed.app, path, JSON_TYPE, padJson(50 * KIB));
			expect(within.status).toBe(200);
			const over = await send(composed.app, path, JSON_TYPE, padJson(150 * KIB));
			expect(over.status).toBe(413);
			expect(over.body).toEqual(TOO_LARGE);
		},
	);

	it.each(TRANSFERS)(
		"the token endpoint still parses past 16 KiB and stops at its 100 KiB beside them, a body sent %s",
		async (_transfer, send) => {
			const headers = { authorization: basic(BINDER) };
			const fields = "grant_type=client_credentials&scope=api.read";
			const within = await send(
				composed.app,
				"/oauth/token",
				FORM_TYPE,
				padForm(50 * KIB, fields),
				headers,
			);
			expect(within.status).toBe(200);
			const over = await send(
				composed.app,
				"/oauth/token",
				FORM_TYPE,
				padForm(150 * KIB, fields),
				headers,
			);
			expect(over.status).toBe(413);
			expect(over.body).toEqual(TOO_LARGE);
		},
	);

	it("the verification route refuses a form with its own 415, beside every other parser", async () => {
		// Signed in, with the CSRF token in its header: past the session and the
		// CSRF guard, the route's own media-type rule is what answers.
		const { agent, header, token } = await signedIn(composed.app);
		const res = await agent
			.post("/oauth/device/verification")
			.set(header, token)
			.type("form")
			.send("action=lookup&user_code=BCDF-GHJK");
		expect(res.status).toBe(415);
		expect(res.body).toEqual({
			error: "invalid_request",
			error_description: "the request body must be application/json",
		});
	});
});

// ---------------------------------------------------------------------------
// Session admission at the link start and WebAuthn registration
// ---------------------------------------------------------------------------

/** A `?link=1` start from this deployment's own page, on the signed-in jar. */
const linkStart = (agent: ReturnType<typeof request.agent>) =>
	agent.get("/session/oauth/federation/google?link=1").set("Sec-Fetch-Site", "same-origin");

describe("session admission at the link start and WebAuthn registration", () => {
	/** Stamps the subject-revocation boundary for alice now, as a credential change does. */
	const revokeAlice = async ({ handle }: FullSet): Promise<void> => {
		const revocation = handle.components.subjectRevocation;
		expect(revocation, "the full set wires subject revocation").toBeDefined();
		await revocation?.revokeBefore(ALICE.sub, new Date(), new Date(Date.now() + 86_400_000));
	};

	it("admits a live session at both, and refuses it at both once alice's sessions are revoked", async () => {
		const set = await boot();
		const { agent, header, token } = await signedIn(set.app);
		expect((await linkStart(agent)).status).toBe(302);
		expect(
			(await agent.post("/oauth/webauthn/registration/options").set(header, token).send({})).status,
		).toBe(200);

		await revokeAlice(set);

		const link = await linkStart(agent);
		expect(link.status).toBe(401);
		expect(link.body.error).toBe("login_required");
		// No subject reaches the registration route: its own 401.
		const registration = await agent
			.post("/oauth/webauthn/registration/options")
			.set(header, token)
			.send({});
		expect(registration.status).toBe(401);
		expect(registration.body.error).toBe("unauthorized");
	});
});

// ---------------------------------------------------------------------------
// Token exchange and the session behind the subject token
// ---------------------------------------------------------------------------

describe("token exchange: a token exchanged from a session-bound token ends with the session", () => {
	// The session grant's token carries the browser session's `sid` and no
	// family, so a logout reaches it only through the UserSession record that
	// introspection reads. A token exchanged from it must keep that link, or it
	// stays active after the logout for the rest of its life.

	/** Signed in, a session-grant token for the web client, and the gateway's exchange of it. */
	const sessionAndExchange = async (app: Express) => {
		const signed = await signedIn(app);
		const minted = await signed.agent
			.post("/oauth/token")
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ grant_type: "session", scope: "openid profile" });
		expect(minted.status).toBe(200);
		const original = minted.body.access_token as string;
		const exchanged = await exchangeAsGateway(app, original);
		expect(exchanged.status).toBe(200);
		return { ...signed, original, exchanged: exchanged.body.access_token as string };
	};

	const exchangeAsGateway = (app: Express, subjectToken: string) =>
		request(app).post("/oauth/token").set("Authorization", basic(GATEWAY)).type("form").send({
			grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
			subject_token: subjectToken,
			subject_token_type: ACCESS_TOKEN_TYPE,
		});

	/** Introspected by the client its audience names. */
	const active = async (
		app: Express,
		token: string,
		client: { id: string; secret: string },
	): Promise<unknown> => {
		const res = await request(app)
			.post("/oauth/introspect")
			.set("Authorization", basic(client))
			.type("form")
			.send({ token });
		expect(res.status).toBe(200);
		return res.body.active;
	};

	it("after /session/logout, the session-grant token and the token exchanged from it both introspect inactive", async () => {
		const { app } = await boot();
		const { agent, header, token, original, exchanged } = await sessionAndExchange(app);
		expect(await active(app, original, WEB)).toBe(true);
		expect(await active(app, exchanged, GATEWAY)).toBe(true);

		const logout = await agent.post("/session/logout").set(header, token);
		expect(logout.status).toBe(200);

		expect(await active(app, original, WEB)).toBe(false);
		expect(await active(app, exchanged, GATEWAY)).toBe(false);
		// Because the exchanged token names the same browser session — as a
		// liveness link, never as the `sid` its capabilities are authorised on.
		expect(tokenPayload(exchanged).liveness_sid).toBe(tokenPayload(original).sid);
		expect(tokenPayload(exchanged)).not.toHaveProperty("sid");
	});

	it("after /session/logout, /userinfo refuses the exchanged token as it refuses the original", async () => {
		const { app } = await boot();
		const { agent, header, token, original, exchanged } = await sessionAndExchange(app);
		expect((await agent.post("/session/logout").set(header, token)).status).toBe(200);
		for (const accessToken of [original, exchanged]) {
			const res = await request(app)
				.get("/oauth/userinfo")
				.set("Authorization", `Bearer ${accessToken}`);
			expect(res.status).toBe(401);
			expect(res.body.error_description).toBe("session_invalid");
		}
	});

	it("refuses to exchange a session-bound token after its session logged out", async () => {
		const { app } = await boot();
		const { agent, header, token, original } = await sessionAndExchange(app);
		expect((await agent.post("/session/logout").set(header, token)).status).toBe(200);

		const again = await exchangeAsGateway(app, original);
		expect(again.status).toBe(400);
		expect(again.body).toEqual({
			error: "invalid_request",
			error_description: "session_invalid",
		});
	});
});

describe("token exchange: an exchanged token reaches none of the capabilities its session's own tokens have", () => {
	// The session link an exchanged token carries is for liveness — it goes
	// inactive when the session ends — and for nothing else. A `sid` claim is
	// also what /userinfo releases the session's claims on, what
	// `POST /oauth/federation/:name/logout` deletes the upstream tokens on, and
	// (with `family_id` and an allowlisted `azp`) what the federation token
	// route hands the upstream access token out on. A downstream holder of an
	// exchanged token must reach none of them. The gateway is registered for
	// `email` and allowlisted for federation tokens, so nothing but the
	// missing session capability stands in the way.

	const exchangeAsGateway = (app: Express, subjectToken: string, scope?: string) =>
		request(app)
			.post("/oauth/token")
			.set("Authorization", basic(GATEWAY))
			.type("form")
			.send({
				grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
				subject_token: subjectToken,
				subject_token_type: ACCESS_TOKEN_TYPE,
				...(scope === undefined ? {} : { scope }),
			});

	/** A Google login, and the web client's authorization-code tokens from that session. */
	const federatedTokens = async (app: Express, upstreams: FullSet["upstreams"]) => {
		const callback = await (await federatedCallback(app, "google", upstreams.google))();
		expect(callback.status).toBe(302);
		const redeemed = await redeem(app, codeFrom(await authorize(app, cookiesOf(callback))));
		expect(redeemed.status).toBe(200);
		const original = redeemed.body.access_token as string;
		const sid = tokenPayload(original).sid as string;
		expect(typeof sid).toBe("string");
		const exchanged = await exchangeAsGateway(app, original, "openid");
		expect(exchanged.status).toBe(200);
		return { original, sid, exchanged: exchanged.body.access_token as string };
	};

	it("/userinfo answers the exchanged token with its subject alone, not the session's claims", async () => {
		const { app } = await boot();
		const { agent } = await signedIn(app);
		const minted = await agent
			.post("/oauth/token")
			.set("Authorization", basic(WEB))
			.type("form")
			.send({ grant_type: "session", scope: "openid email" });
		expect(minted.status).toBe(200);
		const original = minted.body.access_token as string;
		// The session's own token, for contrast: its scope releases the email.
		const own = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${original}`);
		expect(own.status).toBe(200);
		expect(own.body).toMatchObject({ sub: ALICE.sub, email: "alice@example.com" });

		const exchanged = await exchangeAsGateway(app, original);
		expect(exchanged.status).toBe(200);
		expect(exchanged.body.scope).toContain("email");
		const res = await request(app)
			.get("/oauth/userinfo")
			.set("Authorization", `Bearer ${exchanged.body.access_token as string}`);
		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sub: ALICE.sub });
	});

	it("the federation token route does not hand the upstream token to the exchanged token", async () => {
		const { app, upstreams } = await boot();
		const { exchanged } = await federatedTokens(app, upstreams);
		const res = await request(app)
			.post("/oauth/federation/google/token")
			.set("Authorization", `Bearer ${exchanged}`);
		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "invalid_token", error_description: "missing sid claim" });
		expect(res.body.access_token).toBeUndefined();
	});

	it("the federation logout route does not let the exchanged token delete the upstream tokens", async () => {
		const { app, upstreams, handle } = await boot();
		const { exchanged, sid } = await federatedTokens(app, upstreams);
		const store = handle.components.federationTokenStore;
		expect(await store?.get(sid, "google")).not.toBeNull();

		const res = await request(app)
			.post("/oauth/federation/google/logout")
			.set("Authorization", `Bearer ${exchanged}`)
			// A body, as a client sends one: the route reads its optional
			// parameters from it.
			.type("form")
			.send({ state: "s" });
		expect(res.status).toBe(401);
		expect(res.body).toEqual({ error: "invalid_token", error_description: "missing sid claim" });
		expect(await store?.get(sid, "google")).not.toBeNull();
	});
});

// ---------------------------------------------------------------------------
// Outages
// ---------------------------------------------------------------------------

const WEBAUTHN_OPTIONS = "/oauth/webauthn/authentication/options";

const OUTAGES: readonly OutageCase<FullSet>[] = [
	{
		module: "device-grant",
		slot: "deviceCodeStore",
		surface: "POST /oauth/device_authorization",
		run: async (app, outage) => {
			outage.down = true;
			return request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: TV.id });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "device_authorization_store_unavailable",
		defects: {
			"store-field":
				"packages/device-grant `deviceAuthorizationEndpoint.mts`: `device_authorization_store_unavailable` carries `clientId` and `err` but no `store` / `step` / `site` field naming the device-code store",
		},
	},
	{
		module: "device-grant",
		slot: "userSessionStore",
		surface: "POST /oauth/device/verification",
		run: async (app, outage) => {
			const started = await request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: TV.id });
			const { agent, header, token } = await signedIn(app);
			outage.down = true;
			// The approval reads the live UserSession behind the cookie first.
			return agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: started.body.user_code });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
	{
		module: "dpop",
		slot: "replaySeenSet",
		surface: "a DPoP proof at /oauth/token",
		run: async (app, outage) => {
			outage.down = true;
			return request(app)
				.post("/oauth/token")
				.set("Authorization", basic(BINDER))
				.set("DPoP", dpopProof("POST", `${ISSUER}/oauth/token`))
				.type("form")
				.send({ grant_type: "client_credentials" });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "token_binding_unavailable",
		defects: {
			"store-field":
				'core\'s token-binding dispatcher (`packages/core/src/middleware/tokenBinding.mts`): `token_binding_unavailable` names the mechanism and `reason: "replay_store_unavailable"`, but carries no `store` / `step` / `site` field',
		},
	},
	{
		module: "oauth-token-exchange",
		slot: "accessTokenDenylist",
		surface: "the subject_token's revocation check",
		run: async (app, outage) => {
			const { access_token } = await webTokens(app);
			outage.down = true;
			return request(app)
				.post("/oauth/token")
				.set("Authorization", basic(GATEWAY))
				.type("form")
				.send({
					grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
					subject_token: access_token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "token_exchange_validation_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
		defects: {
			"store-field":
				"packages/oauth-token-exchange: `token_exchange_validation_unavailable` names the token's `role` but no `store` / `step` / `site` field",
			"no-warn":
				"core's verifier (`verifyJwt`, `packages/core/src/jwt/verify.mts`) writes its own `jwt_verify_rejected` warn (`reason: \"revocation_unavailable\"`) beside the exchange's error line — the defect the template suite pins at introspection",
		},
	},
	{
		module: "device-grant",
		slot: "subjectRevocation",
		surface: "POST /oauth/device/verification (the sessions boundary)",
		run: async (app, outage) => {
			const started = await request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: TV.id });
			const { agent, header, token } = await signedIn(app);
			outage.down = true;
			return agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: started.body.user_code });
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
	{
		module: "device-grant",
		slot: "subjectRevocation",
		surface: "the device's poll at /oauth/token (the sessions boundary)",
		run: async (app, outage) => {
			const started = await request(app)
				.post("/oauth/device_authorization")
				.type("form")
				.send({ client_id: TV.id });
			const { agent, header, token } = await signedIn(app);
			await agent
				.post("/oauth/device/verification")
				.set(header, token)
				.send({ action: "approve", user_code: started.body.user_code });
			outage.down = true;
			return request(app).post("/oauth/token").type("form").send({
				grant_type: DEVICE_CODE_GRANT_TYPE,
				client_id: TV.id,
				device_code: started.body.device_code,
			});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "device_code_grant_revocation_unavailable",
	},
	{
		module: "oauth-token-exchange",
		slot: "userSessionStore",
		surface: "the subject_token's session check",
		run: async (app, outage) => {
			const { agent } = await signedIn(app);
			const minted = await agent
				.post("/oauth/token")
				.set("Authorization", basic(WEB))
				.type("form")
				.send({ grant_type: "session", scope: "openid profile" });
			outage.down = true;
			return request(app)
				.post("/oauth/token")
				.set("Authorization", basic(GATEWAY))
				.type("form")
				.send({
					grant_type: TOKEN_EXCHANGE_GRANT_TYPE,
					subject_token: minted.body.access_token,
					subject_token_type: ACCESS_TOKEN_TYPE,
				});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "token_exchange_session_store_unavailable",
		unrelatedWarns: ["jwt_verify_aud_skipped"],
	},
	{
		module: "webauthn",
		slot: "challengeStore",
		surface: `POST ${WEBAUTHN_OPTIONS}`,
		run: async (app, outage) => {
			outage.down = true;
			return request(app).post(WEBAUTHN_OPTIONS).send({});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "webauthn_ceremony_store_unavailable",
	},
	{
		module: "webauthn",
		slot: "webauthnCredentialStore",
		surface: "POST /oauth/webauthn/registration/options",
		run: async (app, outage) => {
			const { agent, header, token } = await signedIn(app);
			outage.down = true;
			return agent.post("/oauth/webauthn/registration/options").set(header, token).send({});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "webauthn_ceremony_store_unavailable",
	},
	// A store outage is 503 at every consumer of admission — here the two this
	// package set adds.
	{
		module: "session",
		slot: "userSessionStore",
		surface: "GET /session/oauth/federation/google?link=1 (the link start's session read)",
		run: async (app, outage) => {
			const { agent } = await signedIn(app);
			outage.down = true;
			return linkStart(agent);
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
	{
		module: "webauthn-session-subject",
		slot: "userSessionStore",
		surface: "POST /oauth/webauthn/registration/options (the session-subject module's read)",
		run: async (app, outage) => {
			const { agent, header, token } = await signedIn(app);
			outage.down = true;
			return agent.post("/oauth/webauthn/registration/options").set(header, token).send({});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
	{
		module: "session",
		slot: "subjectRevocation",
		surface: "GET /session/oauth/federation/google?link=1 (the revocation boundary)",
		run: async (app, outage) => {
			const { agent } = await signedIn(app);
			outage.down = true;
			return linkStart(agent);
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
	{
		module: "webauthn-session-subject",
		slot: "subjectRevocation",
		surface: "POST /oauth/webauthn/registration/options (the revocation boundary)",
		run: async (app, outage) => {
			const { agent, header, token } = await signedIn(app);
			outage.down = true;
			return agent.post("/oauth/webauthn/registration/options").set(header, token).send({});
		},
		answer: { status: 503, error: "temporarily_unavailable" },
		event: "session_admission_unavailable",
	},
];

describeOutages(
	"a store outage behind an added module answers 503 and is logged once, at error",
	OUTAGES,
	(outage) => composeFullSet({ outage }),
);
