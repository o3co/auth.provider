import { sessions } from "@mod/session";
import { expect, it } from "vitest";
import { servedEach, until } from "./harness.ts";

const serve = servedEach();

it("keeps the clients a session redeemed codes for, and nothing for one it never closes", async () => {
	const h = await serve();
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	await h.redeemed(session.id, "app");
	expect((await h.stores.clients.members(session.id)).map((m) => m.member)).toEqual(["app"]);
	await new Promise((resolve) => setTimeout(resolve, 1300));
	expect(h.sent).toEqual([]);
});

it("remembers a session's clients until the session ends, however short remember-for is", async () => {
	const h = await serve({ settings: { "remember-for": "1m" } });
	const { session } = await h.login();
	await h.redeemed(session.id, "app");
	h.advance(61_000);
	await h.app.get(sessions).close(session.id);
	await until(() => h.sent.length > 0);
	expect(h.sent.map((s) => s.url)).toEqual(["https://app.example/bc"]);
});

it("remembers a client for remember-for where the session's end is unknown, and no longer", async () => {
	const h = await serve({ settings: { "remember-for": "2h" } });
	await h.redeemed("unknown", "app");
	h.advance(7_199_000);
	expect(await h.stores.clients.members("unknown")).toHaveLength(1);
	h.advance(2000);
	expect(await h.stores.clients.members("unknown")).toEqual([]);
});

it("logs the clients the store pushes out of a session's set", async () => {
	const h = await serve();
	const { session } = await h.login();
	for (const client of ["a", "b", "c", "d"]) await h.redeemed(session.id, client);
	expect(h.logs().filter((l) => l.event === "rp-logout.clients_pushed_out")).toEqual([]);
	await h.redeemed(session.id, "e");
	expect(h.logs().filter((l) => l.event === "rp-logout.clients_pushed_out")).toEqual([
		expect.objectContaining({ level: "warn", fields: { count: 1 } }),
	]);
});
