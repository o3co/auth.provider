import { randomBytes } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { areaTarget } from "@mod/conformance";
import { selfSigned, startFront } from "@mod/conformance-front";
import { startTunnel } from "@mod/conformance-tunnel";
import { drive, makePlan, type SuiteCall } from "../drive/drive.ts";
import { expectedOf } from "../expected/expected.ts";
import {
	cleared,
	keptThenStopped,
	planDirs,
	planWithinMs,
	stopAll,
} from "../lifecycle/lifecycle.ts";
import type { PlanRun } from "../report/report.ts";
import { outcomesOf, testsOf } from "../results/results.ts";
import { keepPages, type ReviewPage } from "../review/review.ts";
import { browser } from "../rp/browser.ts";
import { rpScene } from "../rp/scene.ts";
import { loggedInAs, signIn } from "../rp/signin.ts";
import { hostForSuite, type SuitePin, startSuite, suiteOrigin } from "../suite/suite.ts";

const packageDir = join(import.meta.dirname, "..", "..");

/** A relying party plan: the suite's plan and variant, its configuration, and which of its tests the harness runs how. */
export interface ClientPlanDefinition {
	/** The run's name, as the evidence and the expected files name it. */
	readonly name: string;
	readonly suitePlan: string;
	readonly variant: Readonly<Record<string, string>>;
	readonly configuration: string;
	/** The tests the harness runs, the app refusing each or logging in through it. */
	readonly run: readonly string[];
	/** The tests it does not run, the provider not offering what each asks; each excused by a skip entry of its own. */
	readonly notRun: readonly string[];
}

/**
 * Why the tests a plan declares do not answer the suite's plan, or none: every test of the plan run or
 * not run, never both, and none declared that the plan does not hold.
 */
export function declarationProblem(
	held: readonly string[],
	plan: Pick<ClientPlanDefinition, "run" | "notRun">,
): string | undefined {
	const both = plan.run.filter((t) => plan.notRun.includes(t));
	const declared = [...plan.run, ...plan.notRun];
	const undeclared = held.filter((t) => !declared.includes(t));
	const stray = declared.filter((t) => !held.includes(t));
	const said = [
		...(both.length > 0 ? [`declared both run and not run: ${both.join(", ")}`] : []),
		...(undeclared.length > 0
			? [`declared neither run nor not run: ${undeclared.join(", ")}`]
			: []),
		...(stray.length > 0 ? [`declared, but the plan holds none: ${stray.join(", ")}`] : []),
	];
	return said.length > 0 ? said.join("; ") : undefined;
}

/** The pattern every relying party plan meets: one that logs browsers in through an upstream. */
export const clientPattern = "sso-federated";

/** A relying party plan's title in the report: the suite's plan, unadapted. */
export const clientTitleOf = (plan: ClientPlanDefinition) => `OIDF ${plan.suitePlan}`;

/** What the app answered a sign-in through one suite test, and whom the browser was logged in as after. */
export interface AppSide {
	/** The app started for the test: a description it could not take refuses its start. */
	readonly booted: boolean;
	readonly status: number;
	/** The error the app's answer named, where it named one. */
	readonly error?: string;
	readonly returned: boolean;
	readonly subject?: string;
}

/** A relying party plan as it ran: the report's run, and the app's side of each test it ran. */
export interface ClientPlanRun {
	readonly run: PlanRun;
	readonly sides: Readonly<Record<string, AppSide>>;
	/** The local subject the suite's user is linked to. */
	readonly subject: string;
}

const errorOf = (body: string) => {
	try {
		const parsed = JSON.parse(body) as { error?: unknown };
		return typeof parsed.error === "string" ? parsed.error : undefined;
	} catch {
		return undefined;
	}
};

/**
 * Runs one relying party plan of the suite against the pattern's app: the plan's tests held to what
 * it declares first; each test it runs made, the app started for it once it waits, a browser signed
 * in through it, and the app stopped; then the plan's results read back by its id, the tests it did
 * not run declared.
 */
export async function runClientPlan(plan: ClientPlanDefinition): Promise<ClientPlanRun> {
	if (process.env.CONFORMANCE_PATTERN !== clientPattern) {
		throw new Error(
			`the relying party plans run on the pattern ${clientPattern}: its vitest configuration sets it`,
		);
	}
	const { work, artifacts } = await planDirs(plan.name, process.env.OIDF_ARTIFACTS_DIR);
	const deadline = AbortSignal.timeout(planWithinMs);
	const stops: (() => Promise<unknown>)[] = [];
	const said: string[] = [];
	const tell = (line: string) => said.push(`${new Date().toISOString()} ${line}`);
	let result: ClientPlanRun | undefined;
	let failure: unknown;
	try {
		const expected = await expectedOf(join(packageDir, "expected"), plan.name);
		const pin = JSON.parse(await readFile(join(packageDir, "suite-pin.json"), "utf8")) as SuitePin;
		const host = await hostForSuite();
		const suiteTls = await selfSigned("localhost.emobix.co.uk", join(work, "suite-tls"));
		const suite = await startSuite(
			pin,
			join(work, "suite"),
			host,
			join(artifacts, "suite-server.log"),
			suiteTls,
			{
				signal: deadline,
			},
		);
		stops.push(() => suite.stop());
		const call: SuiteCall = (method, path, body) => suite.call(method, path, body);
		// The suite's host resolves to loopback, which the app's outbound reaches over https by a proxy alone.
		const tunnel = await startTunnel({
			allow: { "localhost.emobix.co.uk:8443": "127.0.0.1:8443" },
		});
		stops.push(() => tunnel.stop());
		let app = "http://127.0.0.1:1";
		const frontTls = await selfSigned("127.0.0.1", join(work, "front"));
		const front = await startFront({
			upstream: () => app,
			publicHost: "127.0.0.1",
			listen: "127.0.0.1",
			tls: frontTls,
		});
		stops.push(
			keptThenStopped(
				() => writeFile(join(artifacts, "rp.log"), `${said.join("\n")}\n`),
				() => front.stop(),
			),
		);
		const alias = `o3co-${plan.name}-${randomBytes(4).toString("hex")}`;
		const client = {
			id: `o3co-${randomBytes(4).toString("hex")}`,
			secret: randomBytes(24).toString("base64url"),
		};
		const user = {
			identifier: "rp-user@example.test",
			subject: `rp-${randomBytes(6).toString("hex")}`,
		};
		const issuer = `${suiteOrigin}/test/a/${alias}/`;
		const returnTarget = "https://rp-return.invalid/back";
		const configuration = {
			alias,
			description: "o3co's federation login as a relying party",
			waitTimeoutSeconds: 5,
			client: {
				client_id: client.id,
				client_secret: client.secret,
				redirect_uri: `${front.origin}/session/oauth/federation/oidf/callback`,
			},
		};
		const trusted = { [front.origin]: frontTls.cert, [suiteOrigin]: suiteTls.cert };
		const pages: ReviewPage[] = [];
		/** Starts the app for one waiting test, signs a browser in through it, and stops the app. */
		const through = async (test: string): Promise<AppSide> => {
			const started = await areaTarget().start(
				rpScene({
					origin: front.origin,
					issuer,
					client,
					user,
					proxy: `http://127.0.0.1:${tunnel.port}`,
					returnTarget,
				}),
				{ trustedCertificates: [suite.certificate] },
			);
			if (started.kind !== "running") {
				tell(`${test}: the app refused to start`);
				pages.push({
					file: `${test}.app.txt`,
					test,
					contentType: "text/plain",
					page: started.output,
				});
				return { booted: false, status: 0, returned: false };
			}
			app = started.baseUrl;
			try {
				const b = browser(trusted);
				const signed = await signIn(b, { origin: front.origin, returnTarget, signal: deadline });
				const subject = await loggedInAs(b, { origin: front.origin, signal: deadline });
				const error = errorOf(signed.callback.body);
				tell(
					`${test}: ${signed.callback.status}${error ? ` ${error}` : ""}, logged in as ${subject ?? "nobody"}`,
				);
				pages.push({
					file: `${test}.app.txt`,
					test,
					contentType: String(signed.callback.headers["content-type"] ?? ""),
					page: signed.callback.body,
				});
				return {
					booted: true,
					status: signed.callback.status,
					...(error ? { error } : {}),
					returned: signed.returned,
					...(subject ? { subject } : {}),
				};
			} finally {
				await started.stop();
			}
		};
		const sides: Record<string, AppSide> = {};
		const waits = { withinMs: 120_000, signal: deadline };
		let incomplete = false;
		const made = await makePlan(call, plan.suitePlan, plan.variant, configuration);
		const problem = declarationProblem(
			made.modules.map((m) => m.testModule),
			plan,
		);
		if (problem !== undefined) throw new Error(`${plan.name}: ${problem}`);
		for (const testModule of plan.run) {
			const driven = await drive(call, made, testModule, () => through(testModule), waits).catch(
				(error: unknown) => {
					incomplete = true;
					tell(`${testModule}: ${String(error)}`);
					return undefined;
				},
			);
			if (driven) sides[testModule] = driven.side;
		}
		const tests = await testsOf(suite.api, plan.suitePlan, made.id);
		await writeFile(join(artifacts, "tests.json"), JSON.stringify(tests, null, 2));
		await keepPages(join(artifacts, "review"), pages);
		const judged = outcomesOf(tests, {
			configuration: plan.configuration,
			failures: expected.failures,
			skips: expected.skips,
			notRun: made.modules
				.filter((m) => plan.notRun.includes(m.testModule))
				.map((m) => ({ testModule: m.testModule, variant: m.variant ?? {} })),
		});
		result = {
			run: {
				...judged,
				driver: { name: "the harness", code: incomplete ? 1 : 0, log: "rp.log" },
				artifacts,
			},
			sides,
			subject: user.subject,
		};
	} catch (error) {
		failure = error;
	}
	const problems = await stopAll(stops);
	await cleared(work, failure, problems);
	if (failure !== undefined) {
		if (problems.length > 0) {
			throw new AggregateError(
				[failure, ...problems],
				`${String(failure)}; and stopping what it started failed`,
			);
		}
		throw failure;
	}
	if (problems.length > 0) {
		throw new AggregateError(
			problems,
			`the plan ran, and stopping what it started failed (left in ${work})`,
		);
	}
	if (result === undefined) throw new Error("the plan ended with no result");
	return result;
}
