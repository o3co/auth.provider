/** A value form-urlencoded, as URLSearchParams writes it: a space is `+`. */
const formEncoded = (value: string) => new URLSearchParams({ "": value }).toString().slice(1);

/** The HTTP Basic client authentication, each part form-urlencoded first (RFC 6749 §2.3.1). */
export function basicAuthorization(clientId: string, secret: string): string {
	const pair = `${formEncoded(clientId)}:${formEncoded(secret)}`;
	return `Basic ${Buffer.from(pair).toString("base64")}`;
}
