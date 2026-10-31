/** This endpoint's URL with `params` as its query, as the flow and the route both write it. */
export const urlFrom =
	(self: string) =>
	(params: Iterable<readonly [string, string]>): string =>
		`${self}?${new URLSearchParams([...params].map(([k, v]) => [k, v]))}`;
