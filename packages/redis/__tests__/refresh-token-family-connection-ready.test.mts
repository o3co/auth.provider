/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * The refresh-token family client's duplicate waits for its connection to be
 * ready before it sends a command, and that wait is bounded by the
 * connection's `commandTimeout`: a server that does not become ready (one
 * loading its dataset answers the ready check's `INFO` with `loading:1`, and
 * ioredis asks again, with no command timed) fails the call as a command
 * timeout would, and readiness arriving after that sends nothing.
 *
 * Real ioredis against real Redis, through a proxy that answers the ready
 * check as a loading server while told to, and records every byte the client
 * sends.
 */

import { once } from "node:events";
import { createServer, type Server, type Socket, connect as tcpConnect } from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { Redis } from "ioredis";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import type { DisposableRefreshTokenFamilyClient } from "#/clients.mjs";
import { makeIoredisClients } from "#/ioredis.mjs";
import { type TestRedis, testRedis } from "./support/redis.mjs";

const COMMAND_TIMEOUT_MS = 1_000;
/** How often ioredis repeats the ready check while the server is loading. */
const LOADING_RETRY_MS = 50;

/** The ready check as ioredis sends it, and a loading server's answer. */
const INFO = "*1\r\n$4\r\ninfo\r\n";
const LOADING_INFO = "loading:1\r\nloading_eta_seconds:1\r\n";
const LOADING_REPLY = `$${LOADING_INFO.length}\r\n${LOADING_INFO}\r\n`;

/** A TCP proxy to Redis that can play a server loading its dataset. */
interface LoadingProxy {
	readonly port: number;
	/** Everything clients have sent, lower-cased, the ready checks it answered included. */
	sent(): string;
	/** While on, the proxy answers every ready check as a loading server. */
	loading(on: boolean): void;
	close(): Promise<void>;
}

async function loadingProxy(upstream: TestRedis): Promise<LoadingProxy> {
	let sent = "";
	let loading = false;
	const sockets = new Set<Socket>();
	const server: Server = createServer((client) => {
		const redis = tcpConnect(upstream.port, upstream.host);
		sockets.add(client).add(redis);
		client.on("data", (data) => {
			const text = data.toString("latin1").toLowerCase();
			sent += text;
			if (loading && text === INFO) client.write(LOADING_REPLY);
			else redis.write(data);
		});
		redis.on("data", (data) => {
			client.write(data);
		});
		const end = () => {
			client.destroy();
			redis.destroy();
		};
		client.on("close", end).on("error", end);
		redis.on("close", end).on("error", end);
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const address = server.address();
	if (address === null || typeof address === "string") throw new Error("proxy has no port");
	return {
		port: address.port,
		sent: () => sent,
		loading: (on) => {
			loading = on;
		},
		close: async () => {
			for (const socket of sockets) socket.destroy();
			server.close();
			await once(server, "close");
		},
	};
}

let at: TestRedis;
let proxy: LoadingProxy;
let parent: Redis;
const opened: DisposableRefreshTokenFamilyClient[] = [];

beforeAll(async () => {
	at = await testRedis();
});

afterEach(async () => {
	for (const conn of opened.splice(0)) await conn[Symbol.asyncDispose]();
	parent?.disconnect();
	await proxy?.close();
});

/**
 * A duplicate of a client whose connection goes through the proxy, with a
 * `commandTimeout`; `loading` is set before the duplicate connects.
 */
async function duplicateThroughProxy(
	loading: boolean,
): Promise<DisposableRefreshTokenFamilyClient> {
	proxy = await loadingProxy(at);
	parent = new Redis({
		host: "127.0.0.1",
		port: proxy.port,
		db: at.db,
		commandTimeout: COMMAND_TIMEOUT_MS,
		maxLoadingRetryTime: LOADING_RETRY_MS,
		lazyConnect: true,
	});
	proxy.loading(loading);
	const conn = makeIoredisClients(parent).refreshTokenFamilyClient.duplicate();
	opened.push(conn);
	return conn;
}

/** The command's settlement, or "pending" when it has none within `withinMs`. */
const settlement = (command: Promise<unknown>, withinMs: number): Promise<unknown> =>
	Promise.race([
		command.then(
			() => "resolved",
			(err: unknown) => err,
		),
		sleep(withinMs).then(() => "pending"),
	]);

describe("the duplicate's wait for a ready connection is bounded by commandTimeout", () => {
	it("a connection that does not become ready fails the command as a command timeout, sending nothing", async () => {
		const conn = await duplicateThroughProxy(true);

		const started = Date.now();
		const outcome = await settlement(conn.watch("rtfam:ready:fam"), COMMAND_TIMEOUT_MS * 10);

		expect(outcome).toBeInstanceOf(Error);
		expect((outcome as Error).message).toBe("Command timed out");
		expect(Date.now() - started).toBeLessThan(COMMAND_TIMEOUT_MS * 5);
		await sleep(COMMAND_TIMEOUT_MS);
		expect(proxy.sent()).not.toContain("watch");
	});

	it("readiness arriving after the timeout sends nothing", async () => {
		const conn = await duplicateThroughProxy(true);
		const outcome = await settlement(conn.watch("rtfam:ready:fam"), COMMAND_TIMEOUT_MS * 10);

		proxy.loading(false);
		await sleep(COMMAND_TIMEOUT_MS * 2);

		expect(outcome).not.toBe("resolved");
		expect(proxy.sent()).not.toContain("watch");
		// Every later command fails too, and sends nothing.
		await expect(conn.get("rtfam:ready:fam")).rejects.toThrow();
		expect(proxy.sent()).not.toMatch(/\bget\b/);
	});

	it("a connection that becomes ready in time is not cut off by the bound", async () => {
		const conn = await duplicateThroughProxy(false);

		await expect(conn.watch("rtfam:ready:fam")).resolves.toBe("OK");
		// Past the bound, the connection still serves.
		await sleep(COMMAND_TIMEOUT_MS * 2);
		await expect(conn.unwatch()).resolves.toBe("OK");
		expect(proxy.sent()).toContain("watch");
	});
});
