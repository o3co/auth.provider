import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, expect, it } from "vitest";
import { entrance, fullApp } from "../full-app.ts";

const scratch = mkdtempSync(join(tmpdir(), "full-app-test-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

it("is refused, before anything is installed, where the tarballs hold no entrance", () => {
	expect(() => fullApp({ "@o3co/auth-provider-oauth": "/t/oauth.tgz" }, scratch)).toThrow(
		`no ${entrance} tarball among the tarballs`,
	);
});
