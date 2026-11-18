/** What a package's manifest declares for the generated project, read into what app-output takes. */
import type { Ask, Asked, Declaring, Sampled } from "@mod/app-output";

/** What a manifest declares for the guide: its lines, the owner it adapts, and the name it registers under it. */
export const askedIn = (
	name: string,
	manifest: Readonly<Record<string, unknown>> | undefined,
): Asked => ({
	name,
	...(Array.isArray(manifest?.asks) ? { asks: manifest.asks as Ask[] } : {}),
	...(typeof manifest?.adapts === "string" ? { adapts: manifest.adapts } : {}),
	...(typeof manifest?.registersAs === "string" ? { registersAs: manifest.registersAs } : {}),
});

/** What a manifest declares of entry samples: the maps it takes them for (`takesSamples`), or the contract its own sample is of (`sampleOf`), with the sample's text. */
export const sampledIn = (
	name: string,
	manifest: Readonly<Record<string, unknown>> | undefined,
	sample: { readonly from: string; readonly text: string } | undefined,
): Sampled => ({
	name,
	...(Array.isArray(manifest?.takesSamples)
		? { takes: manifest.takesSamples as { map: string; of: string }[] }
		: {}),
	...(typeof manifest?.sampleOf === "string" ? { sampleOf: manifest.sampleOf } : {}),
	...(sample ? { sample } : {}),
});

/** What a manifest declares of the app's entries, as written: app-entries reads and refuses it. */
export const entriesIn = (
	name: string,
	manifest: Readonly<Record<string, unknown>> | undefined,
): readonly Declaring[] =>
	manifest?.appEntries === undefined ? [] : [{ name, appEntries: manifest.appEntries }];
