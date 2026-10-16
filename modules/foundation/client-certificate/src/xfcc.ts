import { createHash } from "node:crypto";
import { certificateBlocks } from "./pem.ts";

interface Field {
	readonly key: string;
	readonly value: string;
}

/** The elements of an XFCC header, each its key=value fields; undefined where its grammar breaks. */
function elementsOf(text: string): Field[][] | undefined {
	const elements: Field[][] = [[]];
	let at = 0;
	for (;;) {
		const end = text.slice(at).search(/[=;,"]/);
		if (end === -1 || text[at + end] !== "=") return undefined;
		const key = text.slice(at, at + end).trim();
		if (key === "") return undefined;
		at += end + 1;
		while (text[at] === " " || text[at] === "\t") at++;
		let value = "";
		if (text[at] === '"') {
			for (at++; text[at] !== '"'; at++) {
				if (text[at] === "\\") at++;
				if (at >= text.length) return undefined;
				value += text[at];
			}
			at++;
			while (text[at] === " " || text[at] === "\t") at++;
			if (at < text.length && text[at] !== ";" && text[at] !== ",") return undefined;
		} else {
			const stop = text.slice(at).search(/[;,]/);
			const raw = stop === -1 ? text.slice(at) : text.slice(at, at + stop);
			if (raw.includes('"')) return undefined;
			value = raw.trim();
			at += raw.length;
		}
		elements[elements.length - 1]?.push({ key, value });
		if (at >= text.length) return elements;
		if (text[at] === ",") elements.push([]);
		at++;
	}
}

/** Fields that count, each at most once in an element, in any case. */
const counted = new Set(["hash", "cert", "chain", "subject"]);

/** The client certificate in Envoy's `x-forwarded-client-cert`, held to its one element's Hash. */
export function xfccOf(text: string): { leaf: Buffer; chain: Buffer[] } | undefined {
	const elements = elementsOf(text);
	if (elements?.length !== 1) return undefined;
	const fields = new Map<string, string>();
	for (const { key, value } of elements[0] ?? []) {
		const name = key.toLowerCase();
		if (!counted.has(name)) continue;
		if (fields.has(name)) return undefined;
		fields.set(name, value);
	}
	const leaf = certificateBlocks(fields.get("cert") ?? "");
	const chain = fields.has("chain") ? certificateBlocks(fields.get("chain") ?? "") : [];
	if (leaf?.length !== 1 || !leaf[0] || !chain) return undefined;
	const sum = createHash("sha256").update(leaf[0]).digest("hex");
	if (fields.get("hash")?.toLowerCase() !== sum) return undefined;
	return { leaf: leaf[0], chain };
}
