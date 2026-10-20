/** A grant's issued body as the token endpoint answers it: an empty scope is left out, so every grant answers alike. */
export function answeredBody(
	body: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
	if (body.scope !== "") return body;
	const { scope: _, ...rest } = body;
	return rest;
}
