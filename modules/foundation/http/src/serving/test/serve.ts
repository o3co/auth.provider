import { connect } from "node:net";
import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { afterEach, expect } from "vitest";
import { listening, type PolicyRule, policies, type Route, routes } from "../../contract.ts";
import http from "../../module.ts";
import { declared } from "./declared.ts";

export const quiet = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** A runtime that keeps the events it warns of, its clock at `at()`. */
export function warning(at: () => number = () => 0) {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, clock: { now: at }, log: recorded.log });
	const count = (event: string) =>
		recorded.lines().filter((line) => line.level === "warn" && line.event === event).length;
	return { runtime, count };
}

/** Sends raw bytes and reads the status line of the answer. */
export function rawStatus(port: number, request: string): Promise<number> {
	return new Promise((resolve, reject) => {
		const socket = connect(port, "127.0.0.1", () => socket.end(request));
		let text = "";
		socket.on("data", (chunk) => {
			text += chunk.toString();
		});
		socket.on("end", () => resolve(Number(/^HTTP\/1\.1 (\d{3})/.exec(text)?.[1] ?? 0)));
		socket.on("error", reject);
	});
}

/** What stops the app a test served; each test file that imports this stops it after each test. */
export const served = { stop: async (): Promise<void> => {} };
afterEach(async () => {
	await served.stop();
	served.stop = async () => {};
});

/** http with these http settings and modules, on any free port. */
export function boot(
	settings: Record<string, unknown> = {},
	options: {
		modules?: Module[];
		runtime?: Runtime;
		environment?: "production" | "development";
	} = {},
) {
	return assemble({
		modules: [http, ...(options.modules ?? [])],
		config: {
			...kernelConfig({ environment: options.environment ?? "production" }),
			http: { port: 0, ...settings },
		},
		runtime: options.runtime ?? quiet,
	});
}

/** Boots and starts http with these handlers; the base URL. */
export async function serveWith(handlers: Module, settings = {}, runtime = quiet) {
	const app = await boot(settings, { modules: [handlers], runtime });
	await app.start();
	served.stop = () => app.stop(1000);
	return `http://127.0.0.1:${app.get(listening).port()}`;
}

/** A module contributing these policy rules, then these routes. */
export function handlers(list: readonly Route[], rules: readonly PolicyRule[] = []): Module {
	return defineModule({ name: "handlers", replicaSafe: false, takes: [] }, (m) => [
		...rules.map((rule) => m.contribute(policies).by(() => rule)),
		...list.map((route) => m.contribute(routes).by(() => declared(route))),
	]);
}

/** The refusals a boot is refused with, as [where, reason]. */
export async function refusalsOf(booting: Promise<unknown>) {
	const error = await booting.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => [r.where, r.reason]);
}
