/**
 * JSON-safe types for seed payloads.
 *
 * Prisma's `InputJsonValue` will not accept `Record<string, unknown>` — unknown
 * is not assignable to a JSON value — so seed data that lands in a Json column
 * is typed against this instead.
 */

export type JsonValue =
  string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };
