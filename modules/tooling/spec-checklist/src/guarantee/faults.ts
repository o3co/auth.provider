/**
 * The faults a guarantee's `faults:` line and a test's `{fault:<name>}` mark name. Each name's
 * meaning is written at the head of checklist/guarantee.md.
 */
export const faultNames = [
	"Pu",
	"Pd",
	"R",
	"L",
	"S",
	"Lr",
	"Lx",
	"F",
	"Fs",
	"C",
	"K",
	"H2",
	"M",
	"Ev",
	"R0",
	"Wt",
	"Nr",
	"Ta",
] as const;
export type FaultName = (typeof faultNames)[number];

const known = new Set<string>(faultNames);
export const isFaultName = (name: string): name is FaultName => known.has(name);
