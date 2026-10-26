import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { areaTarget } from "@mod/conformance";
import { type FrontRequest, selfSigned, startFront } from "@mod/conformance-front";
import { startTunnel } from "@mod/conformance-tunnel";
import { readChecklist } from "@mod/spec-checklist";
import { type Expected, expectedProblems, suiteEntries } from "../expected/expected.ts";
import { loginPage } from "../login/login.ts";
import { pkceShim } from "../pkce/pkce.ts";
import { type ModuleRun, type Outcome, outcomesOf } from "../results/results.ts";
import { suiteScene } from "../scene/scene.ts";
import {
	hostForSuite,
	type SuitePin,
	SuiteStopFailed,
	startSuite,
	suiteOrigin,
} from "../suite/suite.ts";

const packageDir = join(import.meta.dirname, "..", "..");

/** A plan the harness runs: the suite's plan, its variants as the runner names them, and the configuration it takes. */
export interface PlanDefinition {
	/** The run's name, as the evidence and the expected files name it. */
	readonly name: string;
	readonly suitePlan: string;
	readonly configuration: string;
	/** How the plan logs out: by the redirect alone, or telling the clients on a channel too; the back channel goes to the suite through a proxy. */
	readonly logout?: "redirect" | "backchannel" | "frontchannel";
}

/** A plan as it ran: each suite test's outcome, the expected entries no test used, and the runner's own word. */
export interface PlanRun {
	readonly modules: readonly (ModuleRun & { readonly outcome: Outcome })[];
	readonly unused: readonly Expected[];
	readonly runner: { readonly code: number | null; readonly output: string };
	/** Where the run's records are kept: the shim's additions, the export, the suite's log. */
	readonly artifacts: string;
}

/** The pattern every OP plan meets: the one the design names, never one the environment chose. */
export const pattern = "simple-web";

/**
 * The sender the app is told of: the suite's browser reaches the front from this machine's
 * loopback on a desktop, the address the app takes for its trusted proxy. A documentation address.
 */
const suiteSender = "198.51.100.40";

/** Where a plan keeps its records under the directory named: one of its own, so plans never mix theirs. */
export const artifactsOf = (plan: string, named: string | undefined): string | undefined =>
	named === undefined ? undefined : join(named, plan);

/** A stop that keeps its records first and stops however keeping them went, the records' failure told. */
export const keptThenStopped =
	(keep: () => Promise<void>, stop: () => Promise<void>) => async (): Promise<void> => {
		try {
			await keep();
		} finally {
			await stop();
		}
	};

/** The longest the suite's runner may run a plan. */
const runWithinMs = 15 * 60_000;

/** The longest a whole plan may take, its setup and its run, before its stops; they run past it by budgets of their own. */
const planWithinMs = 25 * 60_000;

/** Runs every stop, the last pushed first, though some fail; answers each failure, none swallowed. */
export async function stopAll(stops: readonly (() => Promise<unknown>)[]): Promise<unknown[]> {
	const problems: unknown[] = [];
	for (const stop of [...stops].reverse()) {
		await stop().catch((error: unknown) => problems.push(error));
	}
	return problems;
}

/**
 * Removes a plan's work directory where everything it started was stopped; keeps it where a stop
 * failed, the suite's start's own too, for it holds what stops that part. A failed removal joins
 * `problems`.
 */
export async function cleared(work: string, failure: unknown, problems: unknown[]): Promise<void> {
	if (problems.length > 0 || failure instanceof SuiteStopFailed) return;
	await rm(work, { recursive: true, force: true }).catch((e: unknown) => problems.push(e));
}

const readJson = async <T>(file: string): Promise<T> =>
	JSON.parse(await readFile(file, "utf8")) as T;

/** The expected entries of a plan, refused before the suite starts where any may not be taken. */
async function expectedOf(name: string) {
	const checklist = readChecklist();
	const known = {
		items: new Map(checklist.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const))),
		decisions: checklist.decisions,
		ledgers: new Map(
			checklist.specs.flatMap((s) => (s.ledger ? [[s.spec, s.ledger] as const] : [])),
		),
	};
	const failures = await readJson<Expected[]>(
		join(packageDir, "expected", `${name}.failures.json`),
	);
	const skips = await readJson<Expected[]>(join(packageDir, "expected", `${name}.skips.json`));
	const problems = [
		...expectedProblems(failures, "failure", known),
		...expectedProblems(skips, "skip", known),
	];
	if (problems.length > 0)
		throw new Error(`the expected entries of ${name} may not be taken:\n${problems.join("\n")}`);
	return { failures, skips };
}

/** What the runner's process said and how it ended, held to the plan's time. */
function runner(
	python: string,
	args: readonly string[],
	cwd: string,
	env: NodeJS.ProcessEnv,
	signal: AbortSignal,
) {
	return new Promise<{ code: number | null; output: string }>((resolve) => {
		execFile(
			python,
			[...args],
			{
				cwd,
				env,
				timeout: runWithinMs,
				signal,
				killSignal: "SIGKILL",
				maxBuffer: 256 * 1024 * 1024,
			},
			(error, stdout, stderr) => {
				const code = error === null ? 0 : typeof error.code === "number" ? error.code : null;
				resolve({ code, output: `${stdout}${stderr}` });
			},
		);
	});
}

/** Each test of the plan the suite ran, read back from its API: its result and its log. */
async function testsOf(
	api: (path: string) => Promise<unknown>,
	planName: string,
): Promise<ModuleRun[]> {
	const listed = (await api("api/plan?length=100")) as {
		readonly data: readonly {
			readonly planName: string;
			readonly modules: readonly {
				readonly testModule: string;
				readonly variant?: Record<string, string>;
				readonly instances: readonly string[];
			}[];
		}[];
	};
	const plan = listed.data.find((p) => p.planName === planName);
	if (plan === undefined) throw new Error(`the suite holds no plan ${planName}`);
	return Promise.all(
		plan.modules.map(async (m) => {
			const instance = m.instances.at(-1);
			const variant = m.variant ?? {};
			if (instance === undefined) return { testModule: m.testModule, variant, log: [] };
			const info = (await api(`api/info/${instance}`)) as { status: string; result: string };
			const log = (await api(`api/log/${instance}`)) as ModuleRun["log"];
			return { testModule: m.testModule, variant, instance, info, log };
		}),
	);
}

/**
 * Runs one OP plan of the suite at its pinned version against the pattern's app behind an https
 * front, with the login page and the PKCE shim, and reads each test's outcome back. Everything it
 * starts is stopped, and its directories removed, however the run ends; the records stay in
 * `artifacts`.
 */
export async function runPlan(plan: PlanDefinition): Promise<PlanRun> {
	if (process.env.CONFORMANCE_PATTERN !== pattern) {
		throw new Error(`the OP plans run on the pattern ${pattern}: its vitest configuration sets it`);
	}
	const expected = await expectedOf(plan.name);
	const pin = await readJson<SuitePin>(join(packageDir, "suite-pin.json"));
	const work = await mkdtemp(join(tmpdir(), `interop-oidf-${plan.name}-`));
	const artifacts =
		artifactsOf(plan.name, process.env.OIDF_ARTIFACTS_DIR) ??
		(await mkdtemp(join(tmpdir(), `interop-oidf-artifacts-${plan.name}-`)));
	await mkdir(artifacts, { recursive: true });
	const stops: (() => Promise<unknown>)[] = [];
	// One deadline for the whole plan, its setup and its run; the stops run past it.
	const deadline = AbortSignal.timeout(planWithinMs);
	let result: PlanRun | undefined;
	let failure: unknown;
	try {
		const host = await hostForSuite();
		// The suite answers under a certificate naming its host, so the app's checks of names hold.
		const suiteTls = await selfSigned("localhost.emobix.co.uk", join(work, "suite-tls"));
		const suite = await startSuite(
			pin,
			join(work, "suite"),
			host,
			join(artifacts, "suite-server.log"),
			suiteTls,
			{ signal: deadline },
		);
		stops.push(() => suite.stop());
		// The suite's host resolves to loopback, which the app's outbound reaches over https by a proxy alone.
		const tunnel =
			plan.logout === "backchannel"
				? await startTunnel({ allow: { "localhost.emobix.co.uk:8443": "127.0.0.1:8443" } })
				: undefined;
		if (tunnel) stops.push(() => tunnel.stop());
		const shim = pkceShim();
		const passed: string[] = [];
		let app = "http://127.0.0.1:1";
		const paths = { authorization: "/oauth/authorize", token: "/oauth/token", login: "/login" };
		const isForm = (r: FrontRequest) =>
			(r.headers["content-type"] ?? "").startsWith("application/x-www-form-urlencoded");
		const front = await startFront({
			upstream: () => app,
			publicHost: host.name,
			listen: host.listen,
			sender: suiteSender,
			tls: await selfSigned(host.name, join(work, "front")),
			async handle(r) {
				if (r.url.pathname !== paths.login) return undefined;
				const page = loginPage(app, front.origin);
				if (r.method !== "POST") {
					return {
						status: 200,
						headers: { "content-type": "text/html; charset=utf-8" },
						body: page.form(r.url.searchParams.get("redirect_to")),
					};
				}
				const cookie = r.headers.cookie;
				const answer = await page.submit(new URLSearchParams(r.body.toString()), {
					address: suiteSender,
					...(cookie === undefined ? {} : { cookie }),
				});
				return {
					status: answer.status,
					headers: {
						"content-type": "text/html; charset=utf-8",
						...(answer.headers.location === undefined ? {} : { location: answer.headers.location }),
						...(answer.headers["set-cookie"] === undefined
							? {}
							: { "set-cookie": [...answer.headers["set-cookie"]] }),
					},
					body: answer.body,
				};
			},
			rewrite(r) {
				const url = new URL(r.url);
				if (url.pathname === paths.authorization) {
					if (r.method === "POST" && isForm(r)) {
						return {
							url,
							body: Buffer.from(
								shim.authorization(new URLSearchParams(r.body.toString())).toString(),
							),
						};
					}
					url.search = shim.authorization(url.searchParams).toString();
				}
				if (url.pathname === paths.token && r.method === "POST" && isForm(r)) {
					return {
						url,
						body: Buffer.from(shim.token(new URLSearchParams(r.body.toString())).toString()),
					};
				}
				return { url, body: r.body };
			},
			answered(request, answer) {
				const location = answer.headers.location;
				// The front's log: each request's path and the provider's answer, for a failed run's records.
				passed.push(
					`${new Date().toISOString()} ${request.method} ${request.url.pathname} ${answer.status}${typeof location === "string" ? ` -> ${location.split("?")[0]}` : ""}`,
				);
				if (typeof location === "string") shim.redirected(new URL(location, front.origin).href);
			},
		});
		stops.push(
			keptThenStopped(
				async () => {
					await writeFile(
						join(artifacts, "pkce-shim.json"),
						JSON.stringify(shim.records(), null, 2),
					);
					await writeFile(join(artifacts, "front.log"), `${passed.join("\n")}\n`);
				},
				() => front.stop(),
			),
		);
		const alias = `o3co-${plan.name}-${randomBytes(4).toString("hex")}`;
		const secret = () => randomBytes(24).toString("base64url");
		const secrets = { client: secret(), client2: secret(), post: secret() };
		const user = {
			identifier: "alice@example.test",
			password: secret(),
			name: "Alice Example",
			email: "alice@example.test",
			picture: "https://example.test/alice.png",
		};
		const started = await areaTarget().start(
			suiteScene({
				origin: front.origin,
				suite: suiteOrigin,
				alias,
				user,
				clients: [
					{ id: "client", secret: secrets.client, method: "client_secret_basic" },
					{ id: "client2", secret: secrets.client2, method: "client_secret_basic" },
					{ id: "client_secret_post", secret: secrets.post, method: "client_secret_post" },
				],
				...(plan.logout === undefined
					? {}
					: {
							logout: {
								...(plan.logout === "redirect" ? {} : { channel: plan.logout }),
								...(tunnel ? { proxy: `http://127.0.0.1:${tunnel.port}` } : {}),
							},
						}),
			}),
			{ trustedCertificates: [suite.certificate] },
		);
		if (started.kind !== "running") throw new Error(`the app refused to start:\n${started.output}`);
		stops.push(() => started.stop());
		app = started.baseUrl;
		const run = join(work, "run");
		await mkdir(join(run, "export"), { recursive: true });
		const configuration = basename(plan.configuration);
		const template = await readFile(join(packageDir, "plans", plan.configuration), "utf8");
		const filled = Object.entries({
			ALIAS: alias,
			ORIGIN: front.origin,
			SECRET_CLIENT: secrets.client,
			SECRET_CLIENT2: secrets.client2,
			SECRET_POST: secrets.post,
			USERNAME: user.identifier,
			PASSWORD: user.password,
		}).reduce((text, [key, value]) => text.replaceAll(`{${key}}`, value), template);
		await writeFile(join(run, configuration), filled);
		await writeFile(join(run, "failures.json"), JSON.stringify(suiteEntries(expected.failures)));
		await writeFile(join(run, "skips.json"), JSON.stringify(suiteEntries(expected.skips)));
		const said = await runner(
			suite.python,
			[
				join(suite.scripts, "run-test-plan.py"),
				"--export-dir",
				join(run, "export"),
				"--expected-failures-file",
				join(run, "failures.json"),
				"--expected-skips-file",
				join(run, "skips.json"),
				plan.suitePlan,
				configuration,
			],
			run,
			{
				...process.env,
				CONFORMANCE_SERVER: `${suiteOrigin}/`,
				CONFORMANCE_DEV_MODE: "1",
				DISABLE_SSL_VERIFY: "1",
			},
			deadline,
		);
		await writeFile(join(artifacts, "runner.log"), said.output);
		await cp(join(run, "export"), join(artifacts, "export"), { recursive: true });
		const planName = plan.suitePlan.split("[")[0] ?? plan.suitePlan;
		const tests = await testsOf(suite.api, planName);
		await writeFile(join(artifacts, "tests.json"), JSON.stringify(tests, null, 2));
		const judged = outcomesOf(tests, {
			configuration,
			failures: expected.failures,
			skips: expected.skips,
		});
		result = { ...judged, runner: said, artifacts };
	} catch (error) {
		failure = error;
	}
	const problems = await stopAll(stops);
	// A stop that failed keeps what stops its part in `work`; it is left for the next run to take down.
	await cleared(work, failure, problems);
	if (failure !== undefined) {
		if (problems.length > 0)
			throw new AggregateError(
				[failure, ...problems],
				`${String(failure)}; and stopping what it started failed`,
			);
		throw failure;
	}
	if (problems.length > 0)
		throw new AggregateError(
			problems,
			`the plan ran, and stopping what it started failed (left in ${work})`,
		);
	if (result === undefined) throw new Error("the plan ended with no result");
	return result;
}
