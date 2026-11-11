package Controller;

import Model.User;

/**
 * The login session of the application: who is logged in right now.
 *
 * There is at most one session because the application has one window and
 * one user at a time. The session starts only after a successful login and
 * only for an active role (2 to 5). It never holds the password or its hash.
 *
 * When no session is active, getUsername() returns null and getRole()
 * returns 0, which matches no role, so every access check denies.
 */
public final class Session {

    private static String username = null;
    private static int role = 0;
    private static long startedAt = 0L;

    private Session() {
    }

    /**
     * Starts a session for an authenticated user.
     *
     * @return false when the user is missing or the role is not 2 to 5; in
     *         that case any existing session is ended as well
     */
    public static synchronized boolean start(User user) {
        end();
        if (user == null || user.getUsername() == null) {
            return false;
        }
        if (user.getRole() < SQLite.ROLE_CLIENT || user.getRole() > SQLite.ROLE_ADMIN) {
            return false;
        }
        username = user.getUsername();
        role = user.getRole();
        startedAt = System.currentTimeMillis();
        return true;
    }

    /** Ends the session. Safe to call when there is none. */
    public static synchronized void end() {
        username = null;
        role = 0;
        startedAt = 0L;
    }

    public static synchronized boolean isActive() {
        return username != null && role >= SQLite.ROLE_CLIENT && role <= SQLite.ROLE_ADMIN;
    }

    /** Username of the logged-in user, or null when nobody is logged in. */
    public static synchronized String getUsername() {
        return username;
    }

    /** Role of the logged-in user (2 to 5), or 0 when nobody is logged in. */
    public static synchronized int getRole() {
        return isActive() ? role : 0;
    }

    /** Time the session started in milliseconds, or 0 when there is none. */
    public static synchronized long getStartedAt() {
        return startedAt;
    }
}
