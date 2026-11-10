import {
	assemble,
	BootRefused,
	defineModule,
	kernelConfig,
	type Module,
	type Runtime,
} from "@mod/kernel";
import { quietRuntime, recordingLog } from "@mod/kernel/testing";
import { expect } from "vitest";
import { type HttpServer, httpServers, type ServerInput } from "../src/contract.ts";
import http from "../src/module.ts";

export const quiet = quietRuntime({
	clock: { now: () => 0 },
	random: { bytes: (n) => new Uint8Array(n) },
});

/** A runtime that keeps the events it warns of. */
export function warning() {
	const recorded = recordingLog();
	const runtime = quietRuntime({ ...quiet, log: recorded.log });
	const count = (event: string) =>
		recorded.lines().filter((line) => line.level === "warn" && line.event === event).length;
	return { runtime, count };
}

/** A server double: keeps what it was given and whether it was drained, and reports this port. */
export function double(port = 4321) {
	const seen: { input?: ServerInput; drained: boolean } = { drained: false };
	const server: HttpServer = {
		serve: async (input) => {
			seen.input = input;
			return {
				port,
				drain: async () => {
					seen.drained = true;
				},
			};
		},
	};
	return { seen, server };
}

/** A module contributing this server. */
export const contributing = (name: string, server: HttpServer): Module =>
	defineModule({ name, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(httpServers).by(() => server),
	]);

/** http with these http settings and modules, and a server double unless `servers` says otherwise. */
export function boot(
	settings: Record<string, unknown> = {},
	options: {
		modules?: Module[];
		servers?: Module[];
		runtime?: Runtime;
		environment?: "production" | "development";
	} = {},
) {
	return assemble({
		modules: [
			http,
			...(options.servers ?? [contributing("server", double().server)]),
			...(options.modules ?? []),
		],
		config: {
			...kernelConfig({ environment: options.environment ?? "production" }),
			http: { port: 0, ...settings },
		},
		runtime: options.runtime ?? quiet,
	});
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
