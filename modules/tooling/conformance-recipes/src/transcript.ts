/** The request headers a reader needs to repeat a step; cookies are the browser's and left out. */
const sentShown = ["content-type", "x-csrf-token", "mfa-transaction"];
/** The answer headers a reader acts on. */
const answerShown = ["content-type", "location", "retry-after", "www-authenticate"];

export interface Answer {
	readonly status: number;
	readonly headers: Headers;
	readonly text: string;
}

interface Exchange {
	readonly method: string;
	readonly path: string;
	readonly sent: readonly [string, string][];
	readonly body: string | undefined;
	readonly answer: Answer;
}

/**
 * Calls a running target and keeps each exchange under the block it was made in, to show them as a
 * reader would make them. Values that differ between runs are shown under fixed names: those the
 * flow names, and those of the JSON keys it masks.
 */
export function transcript(base: string, shownOrigin: string) {
	const blocks = new Map<string, Exchange[]>();
	const named = new Map<string, string>([[base, shownOrigin]]);
	const masked = new Map<string, string>();
	let current: Exchange[] | undefined;

	/** Shows every named value under its name, longest first so no name hides part of another. */
	const shown = (text: string) =>
		[...named.entries()]
			.sort(([a], [b]) => b.length - a.length)
			.reduce((t, [value, name]) => t.split(value).join(name), text);
	const maskedJson = (value: unknown): unknown => {
		if (Array.isArray(value)) return value.map(maskedJson);
		if (value === null || typeof value !== "object") return value;
		return Object.fromEntries(
			Object.entries(value).map(([key, v]) => [key, masked.get(key) ?? maskedJson(v)]),
		);
	};
	const bodyText = (text: string) => {
		try {
			return JSON.stringify(maskedJson(JSON.parse(text)), null, 2);
		} catch {
			return text;
		}
	};
	const http = (lines: readonly string[], body: string | undefined) =>
		["```http", ...lines, ...(body ? ["", shown(bodyText(body))] : []), "```"].join("\n");

	return {
		/** Begins the block that the exchanges made from now on belong to. */
		block(name: string): void {
			current = [];
			blocks.set(name, current);
		},
		/** Shows `value`, wherever it appears from here on, as `name`. */
		name(value: string, name: string): void {
			if (value !== "") named.set(value, name);
		},
		/** Shows the value of every JSON member called `key` as `name`. */
		mask(key: string, name: string): void {
			masked.set(key, name);
		},
		/** Makes one request to the target and keeps it in the current block. */
		async send(
			method: string,
			path: string,
			init: { readonly headers?: Record<string, string>; readonly body?: string } = {},
		): Promise<Answer> {
			if (!current) throw new Error("no block begun");
			const response = await fetch(new URL(path, base), {
				method,
				redirect: "manual",
				...(init.headers ? { headers: init.headers } : {}),
				...(init.body === undefined ? {} : { body: init.body }),
			});
			const answer = {
				status: response.status,
				headers: response.headers,
				text: await response.text(),
			};
			const sent = Object.entries(init.headers ?? {})
				.map(([k, v]) => [k.toLowerCase(), v] as [string, string])
				.filter(([k]) => sentShown.includes(k));
			current.push({ method, path, sent, body: init.body, answer });
			return answer;
		},
		/** A block's exchanges as a reader repeats them: each request, then its answer. */
		text(name: string): string {
			const exchanges = blocks.get(name);
			if (!exchanges) throw new Error(`no block ${name}`);
			return exchanges
				.map(({ method, path, sent, body, answer }) => {
					const request = http(
						[`${method} ${shown(path)}`, ...sent.map(([k, v]) => `${k}: ${shown(v)}`)],
						body,
					);
					const headers = answerShown.flatMap((k) => {
						const v = answer.headers.get(k);
						return v === null ? [] : [`${k}: ${shown(v)}`];
					});
					return `${request}\n\n${http([`${answer.status}`, ...headers], answer.text)}`;
				})
				.join("\n\n");
		},
	};
}

export type Transcript = ReturnType<typeof transcript>;
