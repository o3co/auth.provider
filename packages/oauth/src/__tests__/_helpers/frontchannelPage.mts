/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */

/**
 * Reads the front-channel logout page as a browser would enforce it: its
 * Content-Security-Policy as directives, its redirect script, and the
 * attribute values HTML-decoded.
 */

import { createHash } from "node:crypto";

/** A serialized policy as directive name → source list, each name once. */
export function parsePolicy(policy: string): Map<string, string[]> {
	const directives = new Map<string, string[]>();
	for (const part of policy.split(";")) {
		const [name, ...sources] = part.trim().split(/\s+/);
		if (name === undefined || name === "") continue;
		if (directives.has(name)) throw new Error(`directive ${name} appears twice`);
		directives.set(name, sources);
	}
	return directives;
}

/** The sources a fetch directive resolves to: its own, else `default-src`'s. */
export function effectiveSources(policy: Map<string, string[]>, directive: string): string[] {
	return policy.get(directive) ?? policy.get("default-src") ?? [];
}

const ENTITIES: Record<string, string> = {
	"&amp;": "&",
	"&lt;": "<",
	"&gt;": ">",
	"&quot;": '"',
	"&#39;": "'",
};

/** An attribute value as the HTML parser decodes it, for the entities the page writes. */
export function decodeAttribute(value: string): string {
	return value.replace(/&(?:amp|lt|gt|quot|#39);/g, (e) => ENTITIES[e] ?? e);
}

/** Every `<script …>…</script>` in the page: its attributes, decoded, and its text. */
export function scriptsOf(
	html: string,
): Array<{ readonly attributes: Record<string, string>; readonly text: string }> {
	return [...html.matchAll(/<script((?:\s+[a-z-]+="[^"]*")*)>([\s\S]*?)<\/script>/g)].map((m) => ({
		attributes: Object.fromEntries(
			[...(m[1] ?? "").matchAll(/([a-z-]+)="([^"]*)"/g)].map((a) => [
				a[1] ?? "",
				decodeAttribute(a[2] ?? ""),
			]),
		),
		text: m[2] ?? "",
	}));
}

/** The CSP hash source that allows an inline script with exactly this text. */
export const hashSourceOf = (text: string): string =>
	`'sha256-${createHash("sha256").update(text, "utf8").digest("base64")}'`;

/** Each `<iframe src>`, decoded. */
export const iframeSrcsOf = (html: string): string[] =>
	[...html.matchAll(/<iframe src="([^"]*)"/g)].map((m) => decodeAttribute(m[1] ?? ""));

/** How many `Content-Security-Policy` header lines a supertest response carried, as sent. */
export function policyHeaderCount(response: object): number {
	const raw = (response as { res?: { rawHeaders?: unknown } }).res?.rawHeaders;
	if (!Array.isArray(raw)) throw new Error("the response carries no raw headers");
	return raw.filter(
		(name, i) => i % 2 === 0 && String(name).toLowerCase() === "content-security-policy",
	).length;
}
