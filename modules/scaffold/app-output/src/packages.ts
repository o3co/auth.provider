/** What the output takes from where the packages come from; the caller implements it. */
import type { Asked } from "./asked/asked.ts";
import type { Fragment, Sampled } from "./fragments/contract.ts";
import type { OutsideModules } from "./outside/contract.ts";

/** Where the packages an app assembles come from, and how the app names them. */
export interface Packages {
	/** Each name's section example, in the order given; a package without one is skipped. */
	fragments(names: readonly string[]): Promise<Fragment[]>;
	/** What the app depends on to have the names. */
	dependencies(names: readonly string[]): Record<string, string>;
	/** What the app imports a name's entries under. */
	importOf(name: string): string;
	/** Where the app installs each name's card, and its section's defaults where it ships them. */
	cards(names: readonly string[]): Card[];
	/** The release the packages are of, and its repository where stated. */
	release(): Release;
	/** The packages outside the release among the names, as recorded; none where the caller has none. */
	outside?(names: readonly string[]): OutsideModules | undefined;
	/** What each name declares for the guide; none where the caller has none, as an older bundle has. */
	asks?(names: readonly string[]): readonly Asked[];
	/** What each name declares of entry samples, its sample's text among it; none where the caller has none. */
	samples?(names: readonly string[]): readonly Sampled[];
}

/** A module's card and section defaults, as the app installs them, from the app's directory. */
export interface Card {
	readonly name: string;
	readonly card: string;
	readonly references?: string;
	/** Its card's section on what it asks of the deployment, where the card has one. */
	readonly deployment?: string;
}

export interface Release {
	readonly version: string;
	readonly repository?: string;
	/** The integrity the release recorded of each of its bundles and of zod, by name: required to compose packages outside it. */
	readonly integrity?: Readonly<Record<string, string>>;
}
