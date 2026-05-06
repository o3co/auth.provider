/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { consoleLogger, createConsoleLogger } from "../consoleLogger.mjs";

describe("consoleLogger level routing", () => {
	afterEach(() => vi.restoreAllMocks());

	it("routes trace to console.debug", () => {
		const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
		consoleLogger.trace({ x: 1 }, "trace message");
		expect(spy).toHaveBeenCalledWith({ x: 1 }, "trace message");
	});

	it("routes debug to console.debug", () => {
		const spy = vi.spyOn(console, "debug").mockImplementation(() => {});
		consoleLogger.debug({ x: 1 }, "debug message");
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
