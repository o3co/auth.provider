import { BootRefused, type Refusal } from "@mod/kernel";
import { expect } from "vitest";

/** The refusals a boot gives; the test fails when it boots, or throws anything else. */
export async function refusalsOf(booting: Promise<unknown>): Promise<readonly Refusal[]> {
	const refused = await booting.catch((error: unknown) => error);
	expect(refused).toBeInstanceOf(BootRefused);
	return (refused as BootRefused).refusals;
}

/** A Basic header for an id and a secret, form-encoded as RFC 6749 §2.3.1 asks. */
export const basic = (id: string, secret: string) => ({
	authorization: `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString("base64")}`,
});
