import { afterEach, expect, it } from "vitest";
import { type Fake, fakeHttp } from "../src/fake.ts";

let fake: Fake | undefined;
afterEach(() => fake?.stop());

it("keeps every request as it came, and answers as the script says", async () => {
	fake = await fakeHttp((asked, base) =>
		asked.path === "/json"
			? { json: { at: base, q: asked.query.get("q") } }
			: asked.path === "/text"
				? { status: 418, headers: { "x-kind": "teapot" }, text: "short and stout" }
				: { status: 404 },
	);
	const json = await fetch(`${fake.base}/json?q=1`);
	expect([json.status, json.headers.get("content-type"), await json.json()]).toEqual([
		200,
		"application/json",
		{ at: fake.base, q: "1" },
	]);
	const text = await fetch(`${fake.base}/text`, {
		method: "POST",
		body: "a=1",
		headers: { "x-sent": "yes" },
	});
	expect([text.status, text.headers.get("x-kind"), await text.text()]).toEqual([
		418,
		"teapot",
		"short and stout",
	]);
	expect((await fetch(`${fake.base}/nothing`)).status).toBe(404);
	const [, posted] = fake.received;
	expect(fake.received.map((r) => `${r.method} ${r.path}`)).toEqual([
		"GET /json",
		"POST /text",
		"GET /nothing",
	]);
	expect([posted?.body, posted?.headers["x-sent"]]).toEqual(["a=1", "yes"]);
});

it("answers 500 when the script fails, keeps serving, and fails the scene when it stops", async () => {
	const failing = await fakeHttp(async (asked) => {
		if (asked.path === "/broken") throw new Error("the script could not sign");
		return { text: "fine" };
	});
	expect((await fetch(`${failing.base}/broken`)).status).toBe(500);
	expect(await (await fetch(`${failing.base}/ok`)).text()).toBe("fine");
	await expect(failing.stop()).rejects.toThrow(/GET \/broken: the script could not sign/);
});

it("answers bytes as they are", async () => {
	const bytes = new Uint8Array([0, 255, 128, 10, 13]);
	fake = await fakeHttp(() => ({ headers: { "content-type": "application/pkix-crl" }, bytes }));
	const answer = await fetch(`${fake.base}/crl`);
	expect(answer.headers.get("content-type")).toBe("application/pkix-crl");
	expect(new Uint8Array(await answer.arrayBuffer())).toEqual(bytes);
});

it("keeps a request's body as the bytes it came in", async () => {
	const sent = new Uint8Array([0x30, 0x82, 0xff, 0x00, 0xc3]);
	fake = await fakeHttp((asked) => ({ bytes: asked.bytes }));
	const answer = await fetch(`${fake.base}/ocsp`, { method: "POST", body: sent });
	expect(new Uint8Array(await answer.arrayBuffer())).toEqual(sent);
	expect(fake.received[0]?.bytes).toEqual(sent);
});
