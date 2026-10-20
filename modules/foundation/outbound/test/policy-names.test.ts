import * as policy from "@mod/outbound-policy";
import { expect, it } from "vitest";
import { DestinationRefused } from "../src/contract.ts";

it("throws the destination policy's own DestinationRefused, the one a caller catches from either package", () => {
	expect(DestinationRefused).toBe(policy.DestinationRefused);
});
