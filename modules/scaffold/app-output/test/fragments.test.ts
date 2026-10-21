import { join } from "node:path";
import { expect, it } from "vitest";
import {
	envExample,
	fragmentsIn,
	fragmentsOf,
	localConfExample,
	settingsOf,
	writtenOf,
} from "../src/fragments.ts";

const fixtures = join(import.meta.dirname, "fixtures", "collide");

it("names each key's environment variable from the section and the key path, and refuses two keys reading one", async () => {
	const [one, other] = await fragmentsIn([join(fixtures, "one"), join(fixtures, "other")]);
	if (!one || !other) throw new Error("fixtures missing");
	expect(settingsOf([one]).map((s) => [s.key, s.env])).toEqual([
		["audit-http.url", "AUDIT_HTTP_URL"],
		["audit-http.retry.max-ms", "AUDIT_HTTP_RETRY_MAX_MS"],
	]);
	expect(() => settingsOf([one, other])).toThrow(
		"audit-http.url and audit.http-url both read AUDIT_HTTP_URL",
	);
});

it("skips a package without a fragment, and refuses one holding other than one section", async () => {
	expect(await fragmentsIn([join(fixtures, "none")])).toEqual([]);
	await expect(fragmentsIn([join(fixtures, "two")])).rejects.toThrow(
		"does not hold exactly one section",
	);
	await expect(fragmentsIn([join(fixtures, "one"), join(fixtures, "one")])).rejects.toThrow(
		"a second fragment for audit-http",
	);
});

it("keeps a value its owner's example gives in several lines out of the env example, read from env still and written in the local layer", () => {
	const text =
		'k {\n\tid = "REPLACE-KEY-ID"\n\tpem = """-----BEGIN KEY-----\nREPLACE-KEY\n-----END KEY-----"""\n}\n';
	const fragments = fragmentsOf([{ from: "k", text }]);
	expect(settingsOf(fragments).map((s) => s.env)).toEqual(["K_ID", "K_PEM"]);
	expect(envExample(settingsOf(fragments))).not.toContain("K_PEM");
	expect(envExample(settingsOf(fragments))).toContain("# K_ID=REPLACE-KEY-ID");
	expect(writtenOf(fragments)).toEqual([
		{
			key: "k.pem",
			example: '"""-----BEGIN KEY-----\nREPLACE-KEY\n-----END KEY-----"""',
			spansSections: false,
			severalLines: true,
		},
	]);
	expect(localConfExample(fragments)).toContain('# k.pem = """-----BEGIN KEY-----\n# REPLACE-KEY');
});
