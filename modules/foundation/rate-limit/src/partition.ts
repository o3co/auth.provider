import { createHash } from "node:crypto";
import type { Window } from "./contract.ts";

export const partitionOf = (name: string, key: string) =>
	createHash("sha256").update(`${name}\n${key}`).digest("base64url");

/** How long to wait, as a hint: at least a second, never longer than the window. */
export const retryAfterMs = (window: Window, resetAt: number, now: number) =>
	Math.min(window.ms, Math.max(1000, resetAt - now));
