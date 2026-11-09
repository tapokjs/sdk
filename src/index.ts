// Import a runtime-specific entrypoint: @tapokjs/sdk/browser or @tapokjs/sdk/server.
// The root entry only carries the error classes, which both entry points also export.
export { TapokCallbackValidationError, TapokError } from "@tapokjs/core";
export { TapokAuthError, TapokHttpError } from "./errors.ts";
export type { TapokAuthErrorCode } from "./errors.ts";
