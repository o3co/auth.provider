import type { Carried, Taken } from "@mod/upstream-round-trip";
import { z } from "zod";

/** What a round trip carries for federation, a login's or a link's, with what the take gives back. */
export interface Trip {
	readonly redirectTo?: string;
	/** The browser asked the upstream to log in again. */
	readonly prompt?: "login";
	readonly maxAgeSeconds?: number;
	readonly link?: { readonly session: string; readonly subject: string };
	/** When the round trip started, on the kernel's clock. */
	readonly startedAt: number;
	readonly verifier: string;
	readonly nonce: string;
}

/** What federation hands `upstream-round-trip` to carry. */
export type TripCarried = Pick<Trip, "redirectTo" | "prompt" | "maxAgeSeconds" | "link">;

const carried = z.strictObject({
	redirectTo: z.string().optional(),
	prompt: z.literal("login").optional(),
	maxAgeSeconds: z.number().optional(),
	link: z.strictObject({ session: z.string(), subject: z.string() }).optional(),
});

export const toCarried = (trip: TripCarried) => trip as unknown as Carried;
/** What a round trip carried for federation; nothing for a shape this does not know. */
export const carriedOf = (value: Carried): TripCarried | undefined => {
	const read = carried.safeParse(value);
	// The shape checked is the type's own; zod's output loses only its readonly marks.
	return read.success ? (read.data as TripCarried) : undefined;
};
/** The trip a taken round trip carried; nothing for a shape this does not know. */
export const tripOf = (taken: Extract<Taken, { kind: "taken" }>): Trip | undefined => {
	const kept = carriedOf(taken.carried);
	if (!kept) return undefined;
	return { ...kept, startedAt: taken.startedAt, verifier: taken.verifier, nonce: taken.nonce };
};
