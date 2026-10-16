import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { expect, it } from "vitest";
import { ending } from "../ending.ts";

it("tells the observers after the answer's listener returns, never inside it", async () => {
	const order: string[] = [];
	const res = Object.assign(new EventEmitter(), { statusCode: 204, headersSent: true });
	const observers = [
		{
			ended: () => {
				order.push("throwing");
				throw new Error("boom");
			},
		},
		{ ended: () => void order.push("told") },
	];
	const req = { method: "GET" } as IncomingMessage;
	ending(observers, { now: () => 0 }, req, res as unknown as ServerResponse);
	expect(() => res.emit("finish")).not.toThrow();
	order.push("listener returned");
	await new Promise((r) => setImmediate(r));
	expect(order).toEqual(["listener returned", "throwing", "told"]);
});
