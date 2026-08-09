import type { BetterAuthClientPlugin } from "better-auth/client";
import type { invite } from "./index";

/**
 * Client plugin for `@aleix10kst/better-auth-invite`.
 *
 * ```ts
 * import { createAuthClient } from "better-auth/client";
 * import { inviteClient } from "@aleix10kst/better-auth-invite/client";
 *
 * const authClient = createAuthClient({
 *   plugins: [inviteClient()],
 * });
 * ```
 */
export const inviteClient = () => {
	return {
		id: "invite",
		$InferServerPlugin: {} as ReturnType<typeof invite>,
		pathMethods: {
			"/invite/send": "POST",
			"/invite/get": "GET",
			"/invite/accept": "POST",
			"/invite/cancel": "POST",
			"/invite/list": "GET",
			"/invite/resend": "POST",
		},
	} satisfies BetterAuthClientPlugin;
};
