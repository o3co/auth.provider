import { createHash } from "node:crypto";
import { recordingLog } from "@mod/kernel/testing";
import { memoryRecords } from "@mod/records/testing";
import { expect, it } from "vitest";
import type { NoticeBodies } from "../../store.ts";
import { bodyOf, bodyRead, entryOf, entryRead, idOf, keep, move } from "../notice-body.ts";

const notice = { client: "app", session: "h-1", subject: "alice", until: 10_000, jti: "j-1" };

/** Bodies, a queue and the pending notices in memory; a subject in `erased` answered `erased`. */
const placed = () => {
	const stand = memoryRecords<string>(() => 0, { shards: 1, perShard: 100 });
	const pending = memoryRecords<string>(() => 0, { shards: 1, perShard: 100 }).deferred;
	const erased = new Set<string>();
	const bodies: NoticeBodies = {
		create: async (id, body, ms, subject) =>
			erased.has(subject) ? "erased" : stand.records.create(id, body, ms),
		read: stand.records.read,
		remove: stand.records.remove,
	};
	const listed = async (list: { each: typeof pending.each }) => {
		const found: string[] = [];
		await list.each(async (x) => void found.push(x));
		return found;
	};
	const log = recordingLog();
	return { bodies, queue: stand.deferred, pending, erased, listed, log };
};

it("keeps one fixed body form, its id the SHA-256 of that string, a 0.19 notice's retry meeting it", () => {
	const body = bodyOf(notice);
	expect(body).toBe(
		'{"format":1,"client":"app","session":"h-1","subject":"alice","until":10000,"jti":"j-1"}',
	);
	expect(idOf(body)).toBe(createHash("sha256").update(body, "utf8").digest("base64url"));
	// The same notice in another key order, with an `after` and a field it does not know: one body.
	const reordered = { jti: "j-1", until: 10_000, subject: "alice", session: "h-1", client: "app" };
	expect(bodyOf(reordered)).toBe(body);
	expect(bodyRead(idOf(body), body)).toEqual(notice);
	expect(bodyRead(idOf(body), body.replace("app", "other"))).toBeUndefined();
	expect(entryRead(entryOf("x", 5))).toEqual({ id: "x", after: 5 });
	expect(entryRead("not an entry")).toBeUndefined();
});

it("adds an entry only once the body is kept, created or there already, and none where the subject is erased", async () => {
	const p = placed();
	expect(await keep(p, notice, 0)).toBe("kept");
	expect(await keep(p, notice, 0)).toBe("kept");
	const id = idOf(bodyOf(notice));
	expect(await p.bodies.read(id)).toBe(bodyOf(notice));
	expect(await p.listed(p.queue)).toEqual([entryOf(id)]);
	p.erased.add("bob");
	expect(await keep(p, { ...notice, subject: "bob" }, 0)).toBe("erased");
	expect(await p.listed(p.queue)).toEqual([entryOf(id)]);
});

it("moves a 0.19 notice to its body and an entry keeping its wait, then done; drops one past its time or unreadable", async () => {
	const p = placed();
	const late = JSON.stringify({ ...notice, after: 7000, extra: true });
	for (const one of [late, JSON.stringify({ ...notice, until: 1 }), "not a notice"]) {
		await p.pending.add(one);
	}
	expect(await move(p, late, p.log.log, 5000)).toBe("moved");
	expect(await p.listed(p.queue)).toEqual([entryOf(idOf(bodyOf(notice)), 7000)]);
	expect(await move(p, JSON.stringify({ ...notice, until: 1 }), p.log.log, 5000)).toBe("dropped");
	expect(await move(p, "not a notice", p.log.log, 5000)).toBe("dropped");
	expect(await p.listed(p.pending)).toEqual([]);
	expect(p.log.lines().map((l) => l.event)).toEqual([
		"rp-logout.notice_expired",
		"rp-logout.notice_unreadable",
	]);
});

it("does a 0.19 notice whose subject is erased, keeping and sending nothing, logged naming no subject", async () => {
	const p = placed();
	const one = JSON.stringify(notice);
	await p.pending.add(one);
	p.erased.add("alice");
	expect(await move(p, one, p.log.log, 0)).toBe("withheld");
	expect([await p.listed(p.pending), await p.listed(p.queue)]).toEqual([[], []]);
	expect(p.log.lines()).toEqual([
		expect.objectContaining({ event: "rp-logout.notice_withheld", fields: { client: "app" } }),
	]);
});
