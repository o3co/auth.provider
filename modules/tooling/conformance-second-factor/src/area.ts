import { area } from "@mod/conformance";

/** Second factors (TOTP and recovery codes) at password login, and step-up. */
export interface SecondFactorPart {
	readonly mode: "optional" | "required";
	/** A code by mail as a second factor, sent to the fake SMTP relay at `host` and `port`; no proof of the address before a first binding. */
	readonly mail?: {
		readonly host: string;
		readonly port: number;
		/** Whether its proof adds `mfa`, so it counts; true unless a scene states otherwise (`mfa-email`'s default is false). */
		readonly addsSecondFactor?: boolean;
	};
	/** The lockout's numbers, where a scene needs a hold it can reach; each target's defaults otherwise. */
	readonly lockout?: {
		readonly threshold: number;
		readonly backoffSeconds: number;
		/** The longest a hold may grow to; the first hold's length when left out. */
		readonly maxBackoffSeconds?: number;
		readonly budget: number;
		readonly hardLimit: number;
	};
}

export const secondFactorArea = area<SecondFactorPart>("second-factor");

/** Where a target sends a session to raise its second factor, on the deployment's origin. */
export const stepUpPage = "/mfa";
