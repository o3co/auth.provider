import type { Suite } from "../suite/suite.ts";

/** The suite's API as a relying party plan calls it: any method, its status left to the caller. */
export type SuiteCall = Suite["call"];

/** A suite test's state, as its runner tells it. */
export type State = "CREATED" | "CONFIGURED" | "WAITING" | "RUNNING" | "FINISHED" | "INTERRUPTED";

/** A plan the suite made, by its id, and the tests it holds. */
export interface MadePlan {
	readonly id: string;
	readonly modules: readonly {
		readonly testModule: string;
		readonly variant?: Readonly<Record<string, string>>;
	}[];
}

/** One suite test driven: its instance, and what the harness found at the app meanwhile. */
export interface Driven<T> {
	readonly testModule: string;
	readonly instance: string;
	readonly side: T;
	/** The state the suite left the test in. */
	readonly ended: State;
}

const ended: readonly State[] = ["FINISHED", "INTERRUPTED"];

/** A request the suite must answer with one of `ok`: its body, refused otherwise. */
async function answered(
	call: SuiteCall,
	method: "GET" | "POST",
	path: string,
	ok: readonly number[],
	body?: unknown,
): Promise<unknown> {
	const answer = await call(method, path, body);
	if (!ok.includes(answer.status)) {
		throw new Error(`the suite answered ${answer.status} to ${method} ${path.split("?")[0]}`);
	}
	return answer.body;
}

/**
 * Waits until the test is in one of `wanted`, or has ended, by the suite's long poll; a test no
 * longer running is read from its info. Held to `withinMs` and `signal`.
 */
export async function stateOf(
	call: SuiteCall,
	instance: string,
	wanted: readonly State[],
	{ withinMs, signal }: { readonly withinMs: number; readonly signal?: AbortSignal },
): Promise<State> {
	const until = Date.now() + withinMs;
	const states = [...new Set([...wanted, ...ended])].join(",");
	for (;;) {
		signal?.throwIfAborted();
		const left = until - Date.now();
		if (left <= 0) throw new Error(`${instance} was not ${wanted.join(" or ")} in time`);
		// Each poll ends within the request's own time.
		const wait = `api/runner/${instance}/wait-state?states=${states}&timeoutMs=${Math.min(left, 25_000)}`;
		const polled = await call("GET", wait);
		if (polled.status === 404) {
			const info = (await answered(call, "GET", `api/info/${instance}`, [200])) as {
				status?: string;
			};
			return info.status as State;
		}
		if (polled.status !== 200) {
			throw new Error(`the suite answered ${polled.status} to the wait for ${instance}`);
		}
		const answer = polled.body as { state?: string };
		if (answer.state !== undefined) return answer.state as State;
	}
}

/** Makes a plan of `name` under `variant`, configured as given. */
export async function makePlan(
	call: SuiteCall,
	name: string,
	variant: Readonly<Record<string, string>>,
	configuration: unknown,
): Promise<MadePlan> {
	const query = new URLSearchParams({ planName: name, variant: JSON.stringify(variant) });
	const made = (await answered(call, "POST", `api/plan?${query}`, [200, 201], configuration)) as {
		id?: string;
		modules?: { testModule: string; variant?: Record<string, string> }[];
	};
	if (typeof made.id !== "string") throw new Error(`the suite made no plan of ${name}`);
	return { id: made.id, modules: made.modules ?? [] };
}

/**
 * Drives one test of a plan: makes it, waits for it to wait for the relying party, lets `act` go
 * through it at the app, then waits for the suite to end it.
 */
export async function drive<T>(
	call: SuiteCall,
	plan: MadePlan,
	testModule: string,
	act: () => Promise<T>,
	{ withinMs, signal }: { readonly withinMs: number; readonly signal?: AbortSignal },
): Promise<Driven<T>> {
	const query = new URLSearchParams({ test: testModule, plan: plan.id });
	const made = (await answered(call, "POST", `api/runner?${query}`, [200, 201])) as {
		id?: string;
	};
	if (typeof made.id !== "string") throw new Error(`the suite made no test ${testModule}`);
	const instance = made.id;
	const waits = { withinMs, ...(signal ? { signal } : {}) };
	const ready = await stateOf(call, instance, ["WAITING"], waits);
	if (ready !== "WAITING") throw new Error(`${testModule} ended ${ready} before the app was asked`);
	const side = await act();
	return { testModule, instance, side, ended: await stateOf(call, instance, ended, waits) };
}
