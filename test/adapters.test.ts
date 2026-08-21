import BetterSqlite3, { type Database as SqliteDatabase } from "better-sqlite3";
import { APIError, betterAuth } from "better-auth";
import { getMigrations } from "better-auth/db/migration";
import { Kysely, SqliteDialect } from "kysely";
import { afterEach, describe, expect, it } from "vitest";
import {
	invite,
	type InviteOptions,
	type SendInvitationEmailData,
} from "../src/index";

/**
 * Every other suite in this repo runs against better-auth's in-memory
 * adapter: no UNIQUE constraints, no real transactions, and an
 * `incrementOne` that is plain JavaScript object mutation. That leaves
 * the plugin's safety-critical machinery — the atomic claim, the
 * acceptance rollback, the SQL-side list filters, the purge counts and
 * the unique-email backstop — unexercised against a real database.
 *
 * This suite runs the plugin against an in-memory SQLite database
 * (better-sqlite3 driven through kysely, handed to better-auth as
 * `database: { db, type: "sqlite" }`) whose schema is created by
 * better-auth's own migration path (`getMigrations` from
 * `better-auth/db/migration`), never by hand-written DDL. Schema
 * expectations are asserted against `sqlite_master` / `PRAGMA
 * index_list`, not against the plugin's config.
 */

const ADMIN_EMAIL = "admin@example.com";
const ADMIN_PASSWORD = "admin-password-123";
const REDIRECT_URL = "https://app.example.com/accept-invite";

/** Kysely instances to tear down after each test (one database per test). */
const openConnections: Kysely<any>[] = [];

afterEach(async () => {
	while (openConnections.length > 0) {
		await openConnections.pop()!.destroy();
	}
});

interface SqlTestConfig {
	/**
	 * Turn on the kysely adapter's real transactions. Defaults to `false`,
	 * which is both the adapter's documented default and what better-auth's
	 * own SQLite test-utils get, and — see the `transactions` describe
	 * block below — the only setting under which `acceptInvite` currently
	 * completes at all.
	 */
	transaction?: boolean;
}

/**
 * Build a betterAuth instance backed by a *fresh* in-memory SQLite
 * database, with the schema produced by better-auth's migrations for
 * exactly this config (so the `invite` table comes from the plugin's own
 * declared schema rather than from DDL written by this test).
 */
async function createSqlAuth(
	overrides: Partial<InviteOptions> = {},
	config: SqlTestConfig = {},
) {
	const sqlite = new BetterSqlite3(":memory:");
	const db = new Kysely<any>({
		dialect: new SqliteDialect({ database: sqlite }),
	});
	openConnections.push(db);

	const emails: SendInvitationEmailData[] = [];
	const auth = betterAuth({
		baseURL: "http://localhost:3000",
		secret: "better-auth-invite-test-secret-0123456789",
		database: {
			db,
			type: "sqlite",
			transaction: config.transaction ?? false,
		},
		emailAndPassword: { enabled: true },
		user: {
			additionalFields: {
				role: { type: "string", required: false, input: false },
			},
		},
		plugins: [
			invite({
				sendInvitationEmail: async (data) => {
					emails.push(data);
				},
				inviteRedirectURL: REDIRECT_URL,
				...overrides,
			}),
		],
	});

	// better-auth's own migration runner, driven from this exact config, so
	// the invite table is whatever the plugin's `schema` really produces
	const { runMigrations } = await getMigrations(auth.options);
	await runMigrations();

	const ctx = await auth.$context;

	const res = await auth.api.signUpEmail({
		body: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, name: "Admin" },
		returnHeaders: true,
	});
	sqlite
		.prepare(`update "user" set "role" = ? where "email" = ?`)
		.run("admin", ADMIN_EMAIL);

	return {
		auth,
		ctx,
		sqlite,
		db,
		emails,
		adminHeaders: toCookieHeaders(res.headers),
	};
}

function toCookieHeaders(headers: Headers) {
	const cookie = headers
		.getSetCookie()
		.map((c) => c.split(";")[0])
		.join("; ");
	return new Headers({ cookie });
}

/** Raw rows, straight out of SQLite — no adapter conversion in between. */
function query(sqlite: SqliteDatabase, sql: string, ...params: unknown[]) {
	return sqlite.prepare(sql).all(...(params as any[])) as any[];
}

function inviteRows(sqlite: SqliteDatabase) {
	return query(sqlite, `select * from "invite" order by "createdAt"`);
}

function userRows(sqlite: SqliteDatabase, email: string) {
	return query(sqlite, `select * from "user" where "email" = ?`, email);
}

function tableDDL(sqlite: SqliteDatabase, table: string) {
	return query(
		sqlite,
		`select sql from sqlite_master where type = 'table' and name = ?`,
		table,
	)[0]?.sql as string | undefined;
}

function indexList(sqlite: SqliteDatabase, table: string) {
	return sqlite.pragma(`index_list("${table}")`) as any[];
}

function indexColumns(sqlite: SqliteDatabase, index: string) {
	return (sqlite.pragma(`index_info("${index}")`) as any[]).map(
		(c) => c.name as string,
	);
}

/** Columns covered by a DB-enforced UNIQUE constraint (`origin: "u"`). */
function uniqueConstraintColumns(sqlite: SqliteDatabase, table: string) {
	return indexList(sqlite, table)
		.filter((i) => i.unique === 1 && i.origin === "u")
		.flatMap((i) => indexColumns(sqlite, i.name));
}

/** Push an invitation past its expiry, in the adapter's date encoding. */
function expireInvite(sqlite: SqliteDatabase, invitationId: string) {
	sqlite
		.prepare(`update "invite" set "expiresAt" = ? where "id" = ?`)
		.run(new Date(Date.now() - 60_000).toISOString(), invitationId);
}

describe("invite plugin on a real SQLite database", () => {
	describe("schema", () => {
		// WHY: the plugin declares `unique: true` on tokenHash and
		// `index: true` on email/status/createdAt. Nothing has ever checked
		// that better-auth's migration path turns those flags into real DDL,
		// and a silently missing UNIQUE on tokenHash would let a token
		// collision produce two live invitations sharing one token.
		it("materializes the plugin's invite schema as real SQLite DDL: a UNIQUE tokenHash plus the single-column and compound indexes the plugin declares", async () => {
			const { sqlite, auth, adminHeaders } = await createSqlAuth();

			const ddl = tableDDL(sqlite, "invite");
			expect(ddl).toBeTruthy();
			expect(ddl).toContain(`"tokenHash" text not null unique`);

			// the `index: true` fields and the table-level `indexes` (compound,
			// better-auth 1.7+) both become CREATE INDEX statements, in the
			// declared column order — which is what makes them usable as
			// prefixes for the queries listInvites and purgeInvites issue
			const created = indexList(sqlite, "invite").filter(
				(i) => i.origin === "c",
			);
			expect(
				Object.fromEntries(
					created.map((i) => [i.name, indexColumns(sqlite, i.name)]),
				),
			).toEqual({
				invite_email_idx: ["email"],
				invite_createdAt_idx: ["createdAt"],
				invite_status_createdAt_idx: ["status", "createdAt"],
				invite_status_expiresAt_idx: ["status", "expiresAt"],
			});

			// ...and `unique: true` becomes a constraint SQLite enforces
			expect(uniqueConstraintColumns(sqlite, "invite")).toEqual(["tokenHash"]);

			// the table is not just shaped right, it works end to end
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com", name: "Invitee" },
				headers: adminHeaders,
			});
			const [row] = inviteRows(sqlite);
			expect(row.id).toBe(invitation.id);
			expect(row.email).toBe("invitee@example.com");
			expect(row.status).toBe("pending");
			expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/);

			// and the UNIQUE constraint is enforced by the database, not by
			// the plugin: a second row with the same token hash is refused
			expect(() =>
				sqlite
					.prepare(
						`insert into "invite"
						 ("id", "email", "status", "tokenHash", "expiresAt", "inviterId", "createdAt", "updatedAt")
						 values (?, ?, ?, ?, ?, ?, ?, ?)`,
					)
					.run(
						"clashing-invite",
						"other@example.com",
						"pending",
						row.tokenHash,
						row.expiresAt,
						row.inviterId,
						row.createdAt,
						row.updatedAt,
					),
			).toThrow(/UNIQUE constraint failed: invite\.tokenHash/);
		});

		// WHY: the plugin's documented last line of defense against a
		// sign-up racing an acceptance is the database's unique index on
		// `user.email`. The memory adapter enforces no uniqueness at all, so
		// that backstop has only ever existed in code comments.
		it("relies on a user.email unique index that SQLite really enforces", async () => {
			const { sqlite } = await createSqlAuth();

			expect(uniqueConstraintColumns(sqlite, "user")).toContain("email");

			const now = new Date().toISOString();
			expect(() =>
				sqlite
					.prepare(
						`insert into "user"
						 ("id", "name", "email", "emailVerified", "createdAt", "updatedAt")
						 values (?, ?, ?, ?, ?, ?)`,
					)
					.run("duplicate-admin", "Clone", ADMIN_EMAIL, 0, now, now),
			).toThrow(/UNIQUE constraint failed: user\.email/);

			expect(userRows(sqlite, ADMIN_EMAIL)).toHaveLength(1);
		});
	});

	describe("accept", () => {
		// WHY: the whole happy path — claim, user, credential account,
		// acceptedUserId backfill — has only ever run against JavaScript
		// arrays. This asserts it against the rows SQLite actually stores,
		// including the integer encoding of `emailVerified`.
		it("sends, resolves and accepts an invitation end to end, writing a verified user and a credential account", async () => {
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth();

			const invitation = await auth.api.sendInvite({
				body: {
					email: "invitee@example.com",
					name: "Invitee",
					role: "member",
				},
				headers: adminHeaders,
			});
			expect(emails).toHaveLength(1);

			const fetched = await auth.api.getInvite({
				query: { token: emails[0]!.token },
			});
			expect(fetched).toMatchObject({
				email: "invitee@example.com",
				name: "Invitee",
				role: "member",
				status: "pending",
			});

			const accepted = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-123" },
			});
			expect(accepted.user.email).toBe("invitee@example.com");

			const [userRow] = userRows(sqlite, "invitee@example.com");
			expect(userRow).toBeTruthy();
			expect(userRow.id).toBe(accepted.user.id);
			expect(userRow.name).toBe("Invitee");
			expect(userRow.role).toBe("member");
			// SQLite has no boolean type: better-auth stores the flag as 1
			expect(userRow.emailVerified).toBe(1);

			const accountRows = query(
				sqlite,
				`select * from "account" where "userId" = ?`,
				accepted.user.id,
			);
			expect(accountRows).toHaveLength(1);
			expect(accountRows[0].providerId).toBe("credential");
			expect(accountRows[0].password).toBeTruthy();

			const [row] = query(
				sqlite,
				`select * from "invite" where "id" = ?`,
				invitation.id,
			);
			expect(row.status).toBe("accepted");
			expect(row.acceptedUserId).toBe(accepted.user.id);

			// the credential account is usable, so the password really landed
			const signIn = await auth.api.signInEmail({
				body: {
					email: "invitee@example.com",
					password: "invitee-password-123",
				},
			});
			expect(signIn.user.id).toBe(accepted.user.id);
		});

		// WHY: the claim is `incrementOne({ increment: {}, set: {...} })` — a
		// set-only update through an API named for incrementing. On the
		// memory adapter that is a no-op-safe object mutation; on SQL it has
		// to compile to an `UPDATE ... WHERE ... RETURNING`, and an adapter
		// that treated an empty increment as "nothing to do" would leave the
		// invitation unclaimed while the plugin believed it had won.
		it("performs the set-only `incrementOne` claim as a real conditional UPDATE, returning null when the predicate misses", async () => {
			const { ctx, sqlite, auth, adminHeaders } = await createSqlAuth();
			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const tokenHash = inviteRows(sqlite)[0].tokenHash as string;

			const claimed = await ctx.adapter.incrementOne<any>({
				model: "invite",
				where: [
					{ field: "id", value: invitation.id },
					{ field: "status", value: "pending" },
					{ field: "tokenHash", value: tokenHash },
				],
				increment: {},
				set: { status: "accepted", updatedAt: new Date() },
			});
			expect(claimed).toBeTruthy();
			expect(claimed!.status).toBe("accepted");
			// the row on disk changed, not just the returned object
			expect(inviteRows(sqlite)[0].status).toBe("accepted");

			// and it is a guard, not a blind write: the same claim now misses
			const second = await ctx.adapter.incrementOne<any>({
				model: "invite",
				where: [
					{ field: "id", value: invitation.id },
					{ field: "status", value: "pending" },
					{ field: "tokenHash", value: tokenHash },
				],
				increment: {},
				set: { status: "rejected", updatedAt: new Date() },
			});
			expect(second).toBeNull();
			expect(inviteRows(sqlite)[0].status).toBe("accepted");
		});

		// WHY: two people clicking the same invite link at the same moment
		// must not produce two users. The memory adapter cannot demonstrate
		// this because nothing there is atomic; on SQLite the conditional
		// UPDATE above is the only thing between the two requests.
		it("lets exactly one of two concurrent accepts through, and fails the other with a 4xx", async () => {
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth();
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const token = emails[0]!.token;

			const results = await Promise.allSettled([
				auth.api.acceptInvite({
					body: { token, password: "invitee-password-123" },
				}),
				auth.api.acceptInvite({
					body: { token, password: "invitee-password-456" },
				}),
			]);

			const fulfilled = results.filter((r) => r.status === "fulfilled");
			const rejected = results.filter((r) => r.status === "rejected");
			expect(fulfilled).toHaveLength(1);
			expect(rejected).toHaveLength(1);

			const error = (rejected[0] as PromiseRejectedResult).reason;
			expect(error).toBeInstanceOf(APIError);
			expect((error as APIError).statusCode).toBeGreaterThanOrEqual(400);
			expect((error as APIError).statusCode).toBeLessThan(500);
			// it lost on the claim itself, or on the existing-user re-check
			// the claim guards — either way a guard fired, not a crash
			expect(["INVITATION_ALREADY_ACCEPTED", "USER_ALREADY_EXISTS"]).toContain(
				((error as APIError).body as any)?.code,
			);

			const users = userRows(sqlite, "invitee@example.com");
			expect(users).toHaveLength(1);
			expect(inviteRows(sqlite)[0].status).toBe("accepted");
			expect(inviteRows(sqlite)[0].acceptedUserId).toBe(users[0].id);
			expect(
				query(
					sqlite,
					`select * from "account" where "userId" = ?`,
					users[0].id,
				),
			).toHaveLength(1);
		});
	});

	describe("transactions", () => {
		// WHY: `acceptInvite` wraps claim + user + credential account +
		// `onInvitationAccepted` in `runWithTransaction`, and the code
		// comments there distinguish "a real transaction rolls this back"
		// from "the compensating catch covers adapters without one". Which
		// branch a SQL adapter takes has never been established. This pins
		// down that a kysely SQLite adapter configured with
		// `transaction: true` genuinely rolls back — so the failure mode
		// documented in the skipped test below is not SQLite's fault.
		it("gives better-auth a genuinely rolling-back transaction when the kysely adapter is configured with transaction: true", async () => {
			const { ctx, sqlite } = await createSqlAuth({}, { transaction: true });
			const adminId = userRows(sqlite, ADMIN_EMAIL)[0].id as string;

			await expect(
				ctx.adapter.transaction(async (trx) => {
					await trx.create({
						model: "invite",
						data: {
							email: "rollback-probe@example.com",
							status: "pending",
							tokenHash: "f".repeat(64),
							expiresAt: new Date(Date.now() + 60_000),
							inviterId: adminId,
							createdAt: new Date(),
							updatedAt: new Date(),
						},
					});
					// the row is visible inside the transaction...
					expect(await trx.count({ model: "invite" })).toBe(1);
					throw new Error("abort");
				}),
			).rejects.toThrow("abort");

			// ...and gone once it aborts
			expect(inviteRows(sqlite)).toHaveLength(0);
		});

		// WHY: with transactions enabled the acceptance is supposed to be
		// atomic. What actually happens is a deadlock, so the rollback that
		// production code can reach today is the compensating one in
		// `acceptInvite`'s catch block: it deletes the half-created user (and
		// its credential account, via `internalAdapter.deleteUser`) and puts
		// the invitation back to `pending`. This asserts that compensation
		// against real SQL rows — no orphaned verified user, no orphaned
		// credential account, and a token that still works afterwards.
		it("undoes a failed acceptance on SQL: no user row, no account row, and the same token works again", async () => {
			const state = { fail: true };
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth({
				onInvitationAccepted: async () => {
					if (state.fail) throw new Error("provisioning exploded");
				},
			});
			const adminId = userRows(sqlite, ADMIN_EMAIL)[0].id as string;

			const invitation = await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expect(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
			).rejects.toThrow();

			expect(userRows(sqlite, "invitee@example.com")).toHaveLength(0);
			expect(
				query(sqlite, `select * from "account"`).filter(
					(a) => a.userId !== adminId,
				),
			).toHaveLength(0);
			const [row] = query(
				sqlite,
				`select * from "invite" where "id" = ?`,
				invitation.id,
			);
			expect(row.status).toBe("pending");
			// the compensation clears `acceptedUserId` along with the user it
			// pointed at: a released invitation that still named a deleted
			// user would surface a dangling id through `listInvites` if it
			// were then canceled, rejected, or left to expire
			expect(row.acceptedUserId).toBeNull();

			// ...so the very same token still works once provisioning recovers
			state.fail = false;
			const retried = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-123" },
			});
			expect(retried.user.email).toBe("invitee@example.com");
			expect(inviteRows(sqlite)[0].status).toBe("accepted");
			expect(inviteRows(sqlite)[0].acceptedUserId).toBe(retried.user.id);
		});

		/**
		 * SKIPPED BECAUSE IT HANGS FOREVER — this is a real bug in
		 * `src/index.ts`, not a problem with the test.
		 *
		 * `acceptInvite` opens `runWithTransaction(ctx.context.adapter, ...)`
		 * and then, inside the callback, keeps calling
		 * `ctx.context.adapter.incrementOne / findOne / update`.
		 * `ctx.context.adapter` is the *outer* adapter: better-auth publishes
		 * the transaction adapter on AsyncLocalStorage and everything in
		 * better-auth's own code reaches it with
		 * `await getCurrentAdapter(ctx.context.adapter)` (see
		 * `better-auth/dist/db/internal-adapter.mjs` and `with-hooks.mjs`).
		 * The plugin never does, so those three calls run *outside* the
		 * transaction it just opened. Verified consequences:
		 *
		 * - kysely's SQLite dialect holds a single connection behind a mutex,
		 *   so the very first outer-adapter call (the claim) waits for a
		 *   connection the open transaction is holding: permanent deadlock.
		 *   `acceptInvite` never resolves and never rejects. Reproduced with
		 *   `database: { db, type: "sqlite", transaction: true }`; the same
		 *   shape applies to node:sqlite, bun:sqlite and D1 dialects.
		 * - on a pooled driver (postgres/mysql) it will not deadlock, but the
		 *   claim and the `acceptedUserId` backfill land on a different
		 *   connection, so they are NOT covered by the rollback the code
		 *   comments promise.
		 *
		 * FIXED: `acceptInvite` now resolves the adapter once inside the
		 * transaction with `getCurrentAdapter(ctx.context.adapter)` and uses
		 * it for the claim, the status re-read, the `acceptedUserId` update
		 * and the compensating writes. This test is the regression guard —
		 * if the plugin ever reaches for `ctx.context.adapter` inside the
		 * transaction again, it hangs here instead of shipping.
		 */
		it("accepts an invitation when the adapter has transactions enabled", async () => {
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth(
				{},
				{ transaction: true },
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			const accepted = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-123" },
			});
			expect(accepted.user.email).toBe("invitee@example.com");
			expect(inviteRows(sqlite)[0].status).toBe("accepted");
			expect(inviteRows(sqlite)[0].acceptedUserId).toBe(accepted.user.id);
		});

		// WHY: the whole point of the transaction. With a transactional
		// adapter a throwing `onInvitationAccepted` must leave NOTHING
		// behind — no user, no credential account, no claimed invitation —
		// through the database's own rollback rather than the compensating
		// writes the non-transactional path relies on.
		it("rolls the whole acceptance back through the database when provisioning throws", async () => {
			const state = { fail: true };
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth(
				{
					onInvitationAccepted: async () => {
						if (state.fail) throw new Error("provisioning exploded");
					},
				},
				{ transaction: true },
			);
			await auth.api.sendInvite({
				body: { email: "invitee@example.com" },
				headers: adminHeaders,
			});
			await expect(
				auth.api.acceptInvite({
					body: {
						token: emails[0]!.token,
						password: "invitee-password-123",
					},
				}),
			).rejects.toThrow();

			expect(userRows(sqlite, "invitee@example.com")).toHaveLength(0);
			const [row] = inviteRows(sqlite);
			expect(row.status).toBe("pending");
			expect(row.acceptedUserId).toBeNull();

			// and the same token still works once provisioning recovers
			state.fail = false;
			const retried = await auth.api.acceptInvite({
				body: { token: emails[0]!.token, password: "invitee-password-123" },
			});
			expect(retried.user.email).toBe("invitee@example.com");
		});

		// WHY: the deadlock above is specific to `acceptInvite`'s own
		// transaction. `claimOnSignUp` claims from a `user.create.after`
		// hook, which better-auth defers until after its transaction
		// commits — so it must keep working on a transaction-enabled
		// adapter. Worth pinning so a future fix is not mistaken for a
		// regression here.
		it("still claims a pending invitation on direct sign-up when transactions are enabled", async () => {
			const { auth, sqlite, adminHeaders } = await createSqlAuth(
				{},
				{ transaction: true },
			);
			const invitation = await auth.api.sendInvite({
				body: { email: "walkin@example.com", role: "member" },
				headers: adminHeaders,
			});
			await auth.api.signUpEmail({
				body: {
					email: "walkin@example.com",
					password: "direct-password-123",
					name: "Walk In",
				},
			});
			const [row] = query(
				sqlite,
				`select * from "invite" where "id" = ?`,
				invitation.id,
			);
			const [user] = userRows(sqlite, "walkin@example.com");
			expect(row.status).toBe("accepted");
			expect(row.acceptedUserId).toBe(user.id);
			expect(user.role).toBe("member");
		});
	});

	describe("list", () => {
		// WHY: `listInvites` pushes its pending/expired filters into the
		// database query (an `lt` comparison against a date column) and
		// computes `total` from a SQL count. SQLite stores dates as ISO
		// strings, so this is the first time that comparison, that count and
		// limit/offset over the *filtered* set run against real SQL.
		it("filters by status and paginates the filtered set in SQL, including the virtual expired status", async () => {
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth();
			const one = await auth.api.sendInvite({
				body: { email: "one@example.com" },
				headers: adminHeaders,
			});
			const two = await auth.api.sendInvite({
				body: { email: "two@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "three@example.com" },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "four@example.com" },
				headers: adminHeaders,
			});
			// accept the fourth so there is a non-pending row in the mix
			await auth.api.acceptInvite({
				body: { token: emails[3]!.token, password: "four-password-123" },
			});
			expireInvite(sqlite, one.id);
			expireInvite(sqlite, two.id);
			// distinct createdAt values so the sort — and therefore
			// offset-based pagination — is deterministic. `one` is older.
			for (const [i, id] of [one.id, two.id].entries()) {
				sqlite
					.prepare(`update "invite" set "createdAt" = ? where "id" = ?`)
					.run(new Date(1_700_000_000_000 + i * 1000).toISOString(), id);
			}

			const all = await auth.api.listInvites({
				query: {},
				headers: adminHeaders,
			});
			expect(all.total).toBe(4);

			const pending = await auth.api.listInvites({
				query: { status: "pending" },
				headers: adminHeaders,
			});
			expect(pending.total).toBe(1);
			expect(pending.invitations.map((i) => i.email)).toEqual([
				"three@example.com",
			]);

			const accepted = await auth.api.listInvites({
				query: { status: "accepted" },
				headers: adminHeaders,
			});
			expect(accepted.invitations.map((i) => i.email)).toEqual([
				"four@example.com",
			]);

			// the expired set is two rows: `total` reports the filtered count
			// while limit/offset walk that set one row at a time
			const expiredAll = await auth.api.listInvites({
				query: { status: "expired" },
				headers: adminHeaders,
			});
			expect(expiredAll.total).toBe(2);
			for (const invitation of expiredAll.invitations) {
				expect(invitation.status).toBe("expired");
				expect((invitation as any).tokenHash).toBeUndefined();
			}

			const firstPage = await auth.api.listInvites({
				query: { status: "expired", limit: 1 },
				headers: adminHeaders,
			});
			const secondPage = await auth.api.listInvites({
				query: { status: "expired", limit: 1, offset: 1 },
				headers: adminHeaders,
			});
			expect(firstPage.invitations).toHaveLength(1);
			expect(secondPage.invitations).toHaveLength(1);
			expect(firstPage.total).toBe(2);
			expect(secondPage.total).toBe(2);
			expect([
				firstPage.invitations[0]!.email,
				secondPage.invitations[0]!.email,
			]).toEqual(["two@example.com", "one@example.com"]);

			// email filtering is normalized and counted in SQL too
			const byEmail = await auth.api.listInvites({
				query: { email: "Three@Example.com" },
				headers: adminHeaders,
			});
			expect(byEmail.total).toBe(1);
			expect(byEmail.invitations[0]!.email).toBe("three@example.com");
		});
	});

	describe("purge", () => {
		// WHY: `purgeInvites` sums `deleteMany`'s return value, and what
		// `deleteMany` returns is adapter-specific — the memory adapter can
		// report a count a SQL driver would not. This checks both the rows
		// that disappear and the number reported back to the caller.
		it("deletes exactly the finished invitations and reports SQLite's real deleted count", async () => {
			const { auth, sqlite, emails, adminHeaders } = await createSqlAuth();
			await auth.api.sendInvite({
				body: { email: "live@example.com" },
				headers: adminHeaders,
			});
			const expired = await auth.api.sendInvite({
				body: { email: "expired@example.com" },
				headers: adminHeaders,
			});
			expireInvite(sqlite, expired.id);
			const canceled = await auth.api.sendInvite({
				body: { email: "canceled@example.com" },
				headers: adminHeaders,
			});
			await auth.api.cancelInvite({
				body: { invitationId: canceled.id },
				headers: adminHeaders,
			});
			await auth.api.sendInvite({
				body: { email: "rejected@example.com" },
				headers: adminHeaders,
			});
			await auth.api.rejectInvite({ body: { token: emails[3]!.token } });
			await auth.api.sendInvite({
				body: { email: "accepted@example.com" },
				headers: adminHeaders,
			});
			await auth.api.acceptInvite({
				body: { token: emails[4]!.token, password: "accepted-password-1" },
			});
			expect(inviteRows(sqlite)).toHaveLength(5);

			// a window wide enough to cover every row deletes nothing yet
			const untouched = await auth.api.purgeInvites({
				body: { olderThan: 3600 },
				headers: adminHeaders,
			});
			expect(untouched.deleted).toBe(0);
			expect(inviteRows(sqlite)).toHaveLength(5);

			// the default statuses are expired + canceled + rejected
			const purged = await auth.api.purgeInvites({
				body: {},
				headers: adminHeaders,
			});
			expect(purged.deleted).toBe(3);
			expect(
				inviteRows(sqlite)
					.map((r) => r.email)
					.toSorted(),
			).toEqual(["accepted@example.com", "live@example.com"]);

			// accepted rows only go when explicitly asked for
			const second = await auth.api.purgeInvites({
				body: { statuses: ["accepted"] },
				headers: adminHeaders,
			});
			expect(second.deleted).toBe(1);
			expect(inviteRows(sqlite).map((r) => r.email)).toEqual([
				"live@example.com",
			]);

			// a purge that matches nothing reports zero, not a row count
			const empty = await auth.api.purgeInvites({
				body: { statuses: ["canceled"] },
				headers: adminHeaders,
			});
			expect(empty.deleted).toBe(0);
			expect(
				await auth.api.getInvite({ query: { token: emails[0]!.token } }),
			).toMatchObject({ email: "live@example.com" });
		});
	});
});
