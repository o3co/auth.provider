import { kinds } from "@mod/combinations";
import type { Budget } from "./contract.ts";

/** The order and roles of the kinds, in the words `combinations` gives them. */
export const kindRules = {
	kindOrder: [
		[kinds.common],
		[kinds.foundation],
		[kinds.capability],
		[kinds.feature],
		[kinds.adapter],
		[kinds.assembly, kinds.wiring, kinds.verification],
	],
	verificationKind: kinds.verification,
	productKinds: [kinds.foundation, kinds.capability, kinds.feature, kinds.adapter, kinds.wiring],
	wiringKind: kinds.wiring,
	capabilityKind: kinds.capability,
	commonKind: kinds.common,
	capabilityBlind: [kinds.feature],
	runtimeFromKernel: [kinds.foundation, kinds.capability, kinds.feature, kinds.adapter],
	widerSurfaceKinds: [kinds.common, kinds.foundation],
	adapterKind: kinds.adapter,
	featureKind: kinds.feature,
} satisfies Partial<Budget>;
