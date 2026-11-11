package Controller;

/**
 * Writes security events to the logs table.
 *
 * Rules followed by every method:
 *  - The timestamp is taken here, at the moment of the event.
 *  - A password, a password hash or a rejected input value is never logged.
 *  - A username that does not pass the username whitelist is not stored;
 *    the placeholder INVALID_USERNAME is logged in its place. This keeps
 *    attacker-controlled text out of the log viewer.
 *  - Logging never throws. A failure to log returns false.
 */
public final class AuditLogger {

    public static final String AUTH_SUCCESS = "AUTH_SUCCESS";
    public static final String AUTH_FAIL = "AUTH_FAIL";
    public static final String LOCKOUT = "LOCKOUT";
    public static final String LOGOUT = "LOGOUT";
    public static final String REGISTER = "REGISTER";
    public static final String VALIDATION_FAIL = "VALIDATION_FAIL";
    public static final String ACCESS_DENIED = "ACCESS_DENIED";
    public static final String USER_MGMT = "USER_MGMT";
    public static final String PRODUCT_MGMT = "PRODUCT_MGMT";
    public static final String PURCHASE = "PURCHASE";
    public static final String LOG_MGMT = "LOG_MGMT";
    public static final String ERROR = "ERROR";

    public static final String UNAUTHENTICATED = "UNAUTHENTICATED";
    public static final String INVALID_USERNAME = "INVALID_USERNAME";
    public static final String SYSTEM = "SYSTEM";

    private static final int DESCRIPTION_MAX = 200;

    private static SQLite sqlite = null;

    private AuditLogger() {
    }

    public static synchronized void init(SQLite database) {
        sqlite = database;
    }

    /** Writes one event. Returns false when it could not be written. */
    public static synchronized boolean log(String event, String username, String description) {
        try {
            if (sqlite == null || event == null) {
                return false;
            }
            String text = (description == null) ? "" : description;
            if (text.length() > DESCRIPTION_MAX) {
                text = text.substring(0, DESCRIPTION_MAX);
            }
            return sqlite.addLogs(event, safeUsername(username), text, SQLite.now());
        } catch (Exception ex) {
            return false;
        }
    }

    /** The name to store in the log for this username. */
    private static String safeUsername(String username) {
        if (username == null) {
            return UNAUTHENTICATED;
        }
        if (SYSTEM.equals(username) || Validator.isValidUsername(username)) {
            return username;
        }
        return INVALID_USERNAME;
    }

    /* ---------------- Authentication ---------------- */

    public static boolean authSuccess(String username) {
        return log(AUTH_SUCCESS, username, "Login successful");
    }

    /** The reason is for the administrator only. It is never shown to the user. */
    public static boolean authFail(String username, String reason) {
        return log(AUTH_FAIL, username, "Login failed: " + reason);
    }

    public static boolean lockout(String username, int attempts) {
        return log(LOCKOUT, username, "Account disabled after " + attempts + " consecutive failed logins");
    }

    public static boolean logout(String username) {
        return log(LOGOUT, username, "User logged out");
    }

    public static boolean register(String username) {
        return log(REGISTER, username, "Account registered with the Client role");
    }

    /* ---------------- Validation and access control ---------------- */

    /**
     * Records a rejected input. Pass the name of the field and the rule that
     * was broken, never the value that was typed.
     */
    public static boolean validationFail(String username, String field, String rule) {
        return log(VALIDATION_FAIL, username, "Rejected input for " + field + ": " + rule);
    }

    public static boolean accessDenied(String username, int role, String resource) {
        return log(ACCESS_DENIED, username, "Role " + role + " was denied access to " + resource);
    }

    /* ---------------- Management actions and errors ---------------- */

    public static boolean userMgmt(String actor, String description) {
        return log(USER_MGMT, actor, description);
    }

    public static boolean productMgmt(String actor, String description) {
        return log(PRODUCT_MGMT, actor, description);
    }

    public static boolean purchase(String actor, String description) {
        return log(PURCHASE, actor, description);
    }

    public static boolean logMgmt(String actor, String description) {
        return log(LOG_MGMT, actor, description);
    }

    /** Records an internal error. Pass a short description, never a stack trace. */
    public static boolean error(String description) {
        return log(ERROR, SYSTEM, description);
    }
}
