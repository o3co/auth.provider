/** What the output takes from where the packages come from; the caller implements it. */
import type { Fragment } from "./fragments.ts";

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
}
