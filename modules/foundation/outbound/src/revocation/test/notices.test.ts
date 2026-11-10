import { expect, it } from "vitest";
import { noticesOver } from "../notices.ts";

it("warns of a peer revoked or unconfirmed by reason and count alone, each reason once a minute, and at debug where unconfirmed is accepted", () => {
	let now = 0;
	const lines: unknown[][] = [];
	const log = {
		warn: (event: string, fields: object) => lines.push(["warn", event, fields]),
		debug: (event: string, fields: object) => lines.push(["debug", event, fields]),
	};
	const notice = noticesOver(log, () => now, false);
	notice({ kind: "good" });
	notice({ kind: "unconfirmed", reason: "unlisted" });
	notice({ kind: "unconfirmed", reason: "unlisted" });
	notice({ kind: "revoked" });
	notice({ kind: "unconfirmed", reason: "stale" });
	now = 60_000;
	notice({ kind: "unconfirmed", reason: "unlisted" });
	expect(lines).toEqual([
		["warn", "outbound.revocation_unconfirmed", { reason: "unlisted", count: 1 }],
		["warn", "outbound.revocation_revoked", { count: 1 }],
		["warn", "outbound.revocation_unconfirmed", { reason: "stale", count: 1 }],
		// The one held back, counted with this.
		["warn", "outbound.revocation_unconfirmed", { reason: "unlisted", count: 2 }],
	]);
	const accepting = noticesOver(log, () => now, true);
	lines.length = 0;
	accepting({ kind: "unconfirmed", reason: "path" });
	accepting({ kind: "revoked" });
	expect(lines).toEqual([
		["debug", "outbound.revocation_unconfirmed", { reason: "path", count: 1 }],
		["warn", "outbound.revocation_revoked", { count: 1 }],
	]);
});
