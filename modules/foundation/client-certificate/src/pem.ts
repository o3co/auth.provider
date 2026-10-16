/** Padded standard base64. */
export const base64 = /^[A-Za-z0-9+/]+={0,2}$/;

const block = /-----BEGIN CERTIFICATE-----([^-]*)-----END CERTIFICATE-----/g;

/** The certificate blocks a PEM text holds, URL-encoded or not, when it holds nothing else. */
export function certificateBlocks(encoded: string): Buffer[] | undefined {
	let text: string;
	try {
		text = decodeURIComponent(encoded);
	} catch {
		return undefined;
	}
	const bodies = [...text.matchAll(block)].map((found) => found[1]?.replace(/\s+/g, "") ?? "");
	if (text.replace(block, "").trim() !== "" || bodies.length === 0) return undefined;
	if (bodies.some((body) => !base64.test(body))) return undefined;
	return bodies.map((body) => Buffer.from(body, "base64"));
}
