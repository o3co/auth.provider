/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleLogger, createConsoleLogger } from "../consoleLogger.mjs";

describe("consoleLogger level routing", () => {
	afterEach(() => vi.restoreAllMocks());

	// The two sub-info levels are exercised through a trace-level logger: the
	// `consoleLogger` singleton now defaults to `info`, so it drops them by
	// design. What is under test here is the 6-levels-onto-4-console-methods
	// mapping, not the threshold.
	const verbose = createConsoleLogger({}, { level: "trace" });

	it("routes trace to console.debug", () => {
		const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
		verbose.trace({ x: 1 }, "trace message");
		expect(spy).toHaveBeenCalledWith({ x: 1 }, "trace message");
	});

	it("routes debug to console.debug", () => {
		const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
		verbose.debug({ x: 1 }, "debug message");
		expect(spy).toHaveBeenCalledWith({ x: 1 }, "debug message");
	});

	it("routes info to console.info", () => {
		const spy = vi.spyOn(console, "info").mockImplementation(() => {});
		consoleLogger.info({ x: 1 }, "info message");
		expect(spy).toHaveBeenCalledWith({ x: 1 }, "info message");
	});

	it("routes warn to console.warn", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		consoleLogger.warn({ err: new Error("x") }, "warn message");
		expect(spy).toHaveBeenCalledWith({ err: expect.any(Error) }, "warn message");
	});

	it("routes error to console.error", () => {
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		consoleLogger.error({ err: new Error("x") }, "error message");
		expect(spy).toHaveBeenCalledWith({ err: expect.any(Error) }, "error message");
	});

	it("routes fatal to console.error", () => {
		const spy = vi.spyOn(console, "error").mockImplementation(() => {});
		consoleLogger.fatal({ code: "PANIC" }, "fatal message");
		expect(spy).toHaveBeenCalledWith({ code: "PANIC" }, "fatal message");
	});

	it("accepts plain string as first arg (no obj)", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		consoleLogger.warn("plain string message");
		// When string is passed, emit { ...bindings } as obj + the string as msg.
		expect(spy).toHaveBeenCalledWith({}, "plain string message");
	});

	// Copilot review on PR #113: previously the object-first branch always
	// forwarded `msg` to `console[method]`, so `logger.warn({ a: 1 })` printed
	// an extra `undefined` argument. The branch now mirrors the string-first
	// conditional and omits `msg` when it is `undefined`.
	it("object-first call with no msg does NOT forward undefined", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		consoleLogger.warn({ a: 1 });
		expect(spy).toHaveBeenCalledWith({ a: 1 });
		expect(spy).not.toHaveBeenCalledWith({ a: 1 }, undefined);
	});

	it("string-first call with msg + extra args forwards all positional args (pino interpolation)", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		consoleLogger.warn("base %s", "interp1", "interp2");
		expect(spy).toHaveBeenCalledWith({}, "base %s", "interp1", "interp2");
	});
});

describe("consoleLogger.child binding propagation", () => {
	afterEach(() => vi.restoreAllMocks());

	it("child bindings appear in every subsequent log call", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const child = consoleLogger.child({ sid: "abc", requestId: "r1" });
		child.warn({ err: new Error("x") }, "test");
		expect(spy).toHaveBeenCalledWith(
			expect.objectContaining({ sid: "abc", requestId: "r1", err: expect.any(Error) }),
			"test",
		);
	});

	it("per-call obj wins over child bindings on collision", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const child = consoleLogger.child({ sid: "parent-sid" });
		child.warn({ sid: "override-sid" }, "test");
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ sid: "override-sid" }), "test");
	});

	it("nested child() merges bindings cumulatively", () => {
		const spy = vi.spyOn(console, "info").mockImplementation(() => {});
		const child1 = consoleLogger.child({ a: 1 });
		const child2 = child1.child({ b: 2 });
		child2.info({}, "test");
		expect(spy).toHaveBeenCalledWith(expect.objectContaining({ a: 1, b: 2 }), "test");
	});

	it("child(string) uses bindings only (no additional obj merge)", () => {
		const spy = vi.spyOn(console, "info").mockImplementation(() => {});
		const child = consoleLogger.child({ sid: "abc" });
		child.info("plain string with bindings");
		expect(spy).toHaveBeenCalledWith({ sid: "abc" }, "plain string with bindings");
	});
});

describe("createConsoleLogger factory", () => {
	afterEach(() => vi.restoreAllMocks());

	it("returns an independent logger instance with given bindings", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const a = createConsoleLogger({ a: 1 });
		const b = createConsoleLogger({ b: 2 });
		a.warn({}, "test-a");
		b.warn({}, "test-b");
		expect(spy).toHaveBeenNthCalledWith(1, { a: 1 }, "test-a");
		expect(spy).toHaveBeenNthCalledWith(2, { b: 2 }, "test-b");
	});

	it("createConsoleLogger() with no args is equivalent to the singleton root", () => {
		const spy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const root = createConsoleLogger();
		root.warn({ x: 1 }, "test");
		expect(spy).toHaveBeenCalledWith({ x: 1 }, "test");
	});
});

// ---------------------------------------------------------------------------
// Level threshold
//
// The interface has always carried six levels but the console-backed default
// emitted all of them unconditionally, so `trace` and `debug` fired in
// production. On an identity provider that is both noise that buries the
// events an operator needs and a channel that carries request-shaped detail.
// ---------------------------------------------------------------------------

describe("createConsoleLogger level threshold", () => {
	const spies = () => ({
		debug: vi.spyOn(console, "debug").mockImplementation(() => {}),
		info: vi.spyOn(console, "info").mockImplementation(() => {}),
		warn: vi.spyOn(console, "warn").mockImplementation(() => {}),
		error: vi.spyOn(console, "error").mockImplementation(() => {}),
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("defaults to info, dropping trace and debug", async () => {
		const s = spies();
		const logger = createConsoleLogger();

		logger.trace({ a: 1 }, "t");
		logger.debug({ a: 1 }, "d");
		logger.info({ a: 1 }, "i");

		expect(s.debug).not.toHaveBeenCalled();
		expect(s.info).toHaveBeenCalledTimes(1);
	});

	it("emits everything at or above the configured level", async () => {
		const s = spies();
		const logger = createConsoleLogger({}, { level: "warn" });

		logger.info({}, "i");
		logger.warn({}, "w");
		logger.error({}, "e");
		logger.fatal({}, "f");

		expect(s.info).not.toHaveBeenCalled();
		expect(s.warn).toHaveBeenCalledTimes(1);
		// error + fatal both route to console.error.
		expect(s.error).toHaveBeenCalledTimes(2);
	});

	it("silences every level at 'silent'", async () => {
		const s = spies();
		const logger = createConsoleLogger({}, { level: "silent" });

		logger.trace({}, "t");
		logger.info({}, "i");
		logger.fatal({}, "f");

		expect(s.debug).not.toHaveBeenCalled();
		expect(s.info).not.toHaveBeenCalled();
		expect(s.error).not.toHaveBeenCalled();
	});

	it("carries the level into children, which inherit rather than reset it", async () => {
		// A child that silently reverted to the default would leak debug output
		// from exactly the request-scoped loggers most likely to carry detail.
		const s = spies();
		const child = createConsoleLogger({}, { level: "error" }).child({ requestId: "r1" });

		child.warn({}, "w");
		child.error({}, "e");

		expect(s.warn).not.toHaveBeenCalled();
		expect(s.error).toHaveBeenCalledTimes(1);
	});

	it("still merges bindings when the level admits the call", async () => {
		const s = spies();
		createConsoleLogger({ svc: "auth" }, { level: "debug" }).debug({ a: 1 }, "msg");

		expect(s.debug).toHaveBeenCalledWith({ svc: "auth", a: 1 }, "msg");
	});
});
