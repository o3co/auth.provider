import { setting } from "@mod/kernel";
import { z } from "zod";

const lifetime = z.number().int().min(60).max(1800);
const window = z.number().int().min(1).max(86_400);
const whole = z.number().int();

const transactionLifetime = setting
	.duration("s")
	.pipe(lifetime)
	.prefault("10m")
	.describe(
		"How long a transaction waits for its factor, from 1m to 30m in whole seconds, such as `10m`.",
	);
const requestsWindow = setting
	.duration("s")
	.pipe(window)
	.prefault("5m")
	.describe("The window `requests` is counted over, from 1s to 1d in whole seconds, such as `5m`.");
const backoff = setting
	.duration("s")
	.pipe(whole)
	.prefault("15m")
	.describe("The first hold after `threshold` failures, in whole seconds, such as `15m`.");
const maxBackoff = setting
	.duration("s")
	.pipe(whole)
	.prefault("1d")
	.describe("The longest hold, the first doubling up to it, in whole seconds, such as `1d`.");
const budgetWindow = setting
	.duration("s")
	.pipe(whole)
	.prefault("7d")
	.describe("The window `budget` is counted over, in whole seconds, such as `7d`.");
const memory = setting
	.duration("s")
	.pipe(whole)
	.prefault("1d")
	.describe(
		"How long a run of failures is remembered without one, in whole seconds, such as `1d`.",
	);

/**
 * A time under its new name, left absent when not given, so its name in seconds can be read in
 * its place; the time's prefault still states the default. (An optional prefault fills absence;
 * the preprocess between them keeps it.)
 */
const kept = (time: z.ZodType<number, string | undefined>) =>
	z.preprocess((value) => value, time).optional();
/** The time's default, as its prefault reads it. */
const defaultOf = (time: z.ZodType<number, string | undefined>) => time.parse(undefined);

/** A key named before its unit was written: read in place of its new name while its writers move. */
const before = (bounds: z.ZodNumber, instead: string) =>
	bounds
		.optional()
		.describe(
			`Seconds, read in place of \`${instead}\`, which replaces it; giving both refuses boot.`,
		);

/** Refuses a time given under both its names, `[name, old]`: which one the operator meant cannot be told. */
const oneName =
	(pairs: readonly (readonly [string, string])[]) =>
	(s: Record<string, unknown>, ctx: z.RefinementCtx) => {
		for (const [name, old] of pairs) {
			if (s[name] !== undefined && s[old] !== undefined) {
				ctx.addIssue({
					code: "custom",
					message: `${name} replaces ${old}: write one`,
					path: [old],
				});
			}
		}
	};

const lockout = z
	.strictObject({
		threshold: z.number().int().prefault(5),
		backoff: kept(backoff),
		"max-backoff": kept(maxBackoff),
		budget: z.number().int().prefault(10),
		"budget-window": kept(budgetWindow),
		"hard-limit": z.number().int().prefault(100),
		memory: kept(memory),
		"backoff-seconds": before(whole, "backoff"),
		"max-backoff-seconds": before(whole, "max-backoff"),
		"budget-window-seconds": before(whole, "budget-window"),
		"memory-seconds": before(whole, "memory"),
	})
	.superRefine(
		oneName([
			["backoff", "backoff-seconds"],
			["max-backoff", "max-backoff-seconds"],
			["budget-window", "budget-window-seconds"],
			["memory", "memory-seconds"],
		]),
	)
	.transform(
		({
			"backoff-seconds": b,
			"max-backoff-seconds": mb,
			"budget-window-seconds": bw,
			"memory-seconds": m,
			...l
		}) => ({
			...l,
			backoff: l.backoff ?? b ?? defaultOf(backoff),
			"max-backoff": l["max-backoff"] ?? mb ?? defaultOf(maxBackoff),
			"budget-window": l["budget-window"] ?? bw ?? defaultOf(budgetWindow),
			memory: l.memory ?? m ?? defaultOf(memory),
		}),
	);

/** The section as written, before a time given under its name in seconds is read in place of its new name. */
export const written = z.strictObject({
	"transaction-lifetime": kept(transactionLifetime),
	"attempts-per-transaction": z.number().int().min(2).max(10).prefault(5),
	/** Requests allowed per source in each window, over every form the flows take. */
	requests: z.number().int().min(1).max(100_000).prefault(60),
	window: kept(requestsWindow),
	lockout: lockout.prefault({}),
	"transaction-seconds": before(lifetime, "transaction-lifetime"),
	"window-seconds": before(window, "window"),
});

export const section = written
	.superRefine(
		oneName([
			["transaction-lifetime", "transaction-seconds"],
			["window", "window-seconds"],
		]),
	)
	.transform(({ "transaction-seconds": t, "window-seconds": w, ...s }) => ({
		...s,
		"transaction-lifetime": s["transaction-lifetime"] ?? t ?? defaultOf(transactionLifetime),
		window: s.window ?? w ?? defaultOf(requestsWindow),
	}));

export type Settings = z.output<typeof section>;

/** The lockout the proof step keeps under each subject in `rate-limit`. */
export const lockoutName = "mfa";
