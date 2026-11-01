/** The bounds a selection keeps within: longer strings, more values or a larger whole are refused. */
export const selectionLimits = { valueLength: 256, values: 16, bytes: 4096 } as const;
