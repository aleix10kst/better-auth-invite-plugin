import { createAuthClient } from "better-auth/client";
import { describe, expect, it } from "vitest";
import { inviteClient } from "../src/client";

describe("invite client plugin", () => {
	it("registers typed invite routes on the auth client", () => {
		const authClient = createAuthClient({
			baseURL: "http://localhost:3000",
			plugins: [inviteClient()],
		});
		// runtime: proxy-based route objects exist
		expect(typeof authClient.invite.send).toBe("function");
		expect(typeof authClient.invite.get).toBe("function");
		expect(typeof authClient.invite.accept).toBe("function");
		expect(typeof authClient.invite.cancel).toBe("function");
		expect(typeof authClient.invite.list).toBe("function");
		expect(typeof authClient.invite.resend).toBe("function");

		// type-level: these calls must typecheck against the inferred server
		// plugin (never executed).
		const _typeOnly = () => {
			void authClient.invite.send({
				email: "a@b.com",
				name: "A",
				role: "member",
				metadata: { teamId: "t1" },
			});
			void authClient.invite.get({ query: { token: "tok" } });
			void authClient.invite.accept({ token: "tok", password: "password123" });
			// password is optional (requirePassword: false flows)
			void authClient.invite.accept({ token: "tok" });
			void authClient.invite.cancel({ invitationId: "id" });
			void authClient.invite.list({
				query: { status: "pending", email: "a@b.com", limit: 10, offset: 0 },
			});
			void authClient.invite.resend({ invitationId: "id" });
		};
		expect(_typeOnly).toBeTypeOf("function");
	});
});
