package Controller;

import Model.User;

/**
 * Account registration and login.
 *
 * Every method fails closed: when anything unexpected happens, nothing is
 * created and a generic result is returned. Password arrays are overwritten
 * with zeros before a method returns.
 */
public final class AuthService {

    /** Outcome of a registration attempt, with the message shown to the user. */
    public enum RegisterResult {
        SUCCESS("Registration successful. You may now log in."),
        INVALID_USERNAME("Username must be " + Validator.USERNAME_MIN + " to " + Validator.USERNAME_MAX
            + " characters long and contain letters and digits only."),
        INVALID_PASSWORD("Password must be " + Validator.PASSWORD_MIN + " to " + Validator.PASSWORD_MAX
            + " characters long and contain at least one uppercase letter, one lowercase letter,"
            + " one digit and one symbol. Spaces are not allowed."),
        PASSWORD_MISMATCH("The passwords do not match."),
        UNAVAILABLE("Registration could not be completed. Please try a different username."),
        ERROR("Registration could not be completed. Please try again later.");

        private final String message;

        RegisterResult(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }

    private static SQLite sqlite = null;

    private AuthService() {
    }

    public static synchronized void init(SQLite database) {
        sqlite = database;
    }

    /**
     * Registers a new account with the Client role (2).
     *
     * Steps: validate the username against the whitelist, validate the
     * password against the policy, check that both entries match, check that
     * no existing username is the same when upper and lower case are ignored,
     * hash the password with PBKDF2 and insert the account. Input that fails
     * a check is rejected as it is; nothing is trimmed or corrected. The role
     * is fixed here and cannot be chosen by the person registering.
     */
    public static synchronized RegisterResult register(String username, char[] password, char[] confirmation) {
        try {
            if (sqlite == null) {
                return RegisterResult.ERROR;
            }
            if (!Validator.isValidUsername(username)) {
                AuditLogger.validationFail(null, "registration username", "must be 4-20 letters and digits");
                return RegisterResult.INVALID_USERNAME;
            }
            if (!Validator.isValidPassword(password)) {
                AuditLogger.validationFail(username, "registration password", "does not meet the password policy");
                return RegisterResult.INVALID_PASSWORD;
            }
            if (!Validator.passwordsMatch(password, confirmation)) {
                AuditLogger.validationFail(username, "registration password", "confirmation does not match");
                return RegisterResult.PASSWORD_MISMATCH;
            }
            if (!sqlite.isUsernameAvailable(username)) {
                AuditLogger.log(AuditLogger.REGISTER, username, "Registration rejected: username not available");
                return RegisterResult.UNAVAILABLE;
            }
            String hash = PasswordUtil.hash(password);
            if (hash == null) {
                AuditLogger.error("Registration failed: password could not be hashed");
                return RegisterResult.ERROR;
            }
            if (!sqlite.addUser(username, hash, SQLite.ROLE_CLIENT)) {
                AuditLogger.error("Registration failed: account could not be saved");
                return RegisterResult.ERROR;
            }
            AuditLogger.register(username);
            return RegisterResult.SUCCESS;
        } catch (Exception ex) {
            return RegisterResult.ERROR;
        } finally {
            PasswordUtil.wipe(password);
            PasswordUtil.wipe(confirmation);
        }
    }

    /** The one message shown for every failed login, whatever the cause. */
    public static final String LOGIN_FAILED_MESSAGE = "Invalid username and/or password";

    /** Consecutive failed logins that disable an account. */
    public static final int MAX_FAILED_ATTEMPTS = 5;

    /** Outcome of a login attempt. */
    public static final class LoginResult {

        private final boolean success;
        private final String lastAttemptTs;
        private final String lastAttemptStatus;

        private LoginResult(boolean success, String lastAttemptTs, String lastAttemptStatus) {
            this.success = success;
            this.lastAttemptTs = lastAttemptTs;
            this.lastAttemptStatus = lastAttemptStatus;
        }

        public boolean isSuccess() {
            return success;
        }

        /** Failure message. It is the same for every kind of failure. */
        public String getMessage() {
            return success ? "" : LOGIN_FAILED_MESSAGE;
        }

        /**
         * Report of the last use of the account before this login: the
         * timestamp and whether that attempt succeeded or failed.
         */
        public String getLastUseReport() {
            if (!success) {
                return "";
            }
            if (lastAttemptTs == null || lastAttemptStatus == null) {
                return "This is the first recorded login attempt for this account.";
            }
            String status = SQLite.STATUS_SUCCESS.equals(lastAttemptStatus) ? "SUCCESSFUL" : "FAILED";
            return "Last login attempt: " + lastAttemptTs + "\nStatus: " + status;
        }
    }

    private static final LoginResult DENIED = new LoginResult(false, null, null);

    /**
     * Authenticates a user and starts the session.
     *
     * The answer starts as "denied" and becomes "granted" only at the very
     * end, after every check has passed. Any error on the way leaves it
     * denied. The caller receives the same result for an unknown username, a
     * wrong password, a disabled account and an internal error, so the
     * screen cannot be used to find out which usernames exist.
     *
     * A password check is always carried out, with a dummy hash when there
     * is no account to check against, so that each of those cases takes
     * about the same time.
     *
     * Each failure on an existing account adds 1 to its failed-login
     * counter. The fifth consecutive failure disables the account (role 1).
     * A successful login resets the counter.
     */
    public static synchronized LoginResult login(String username, char[] password) {
        LoginResult result = DENIED;
        try {
            Session.end();
            if (sqlite == null) {
                return DENIED;
            }

            // 1. Input validation. A rejected value is not used for anything.
            if (!Validator.isValidUsername(username)) {
                PasswordUtil.dummyVerify(password);
                AuditLogger.validationFail(null, "login username", "must be 4-20 letters and digits");
                AuditLogger.authFail(null, "invalid username format");
                return DENIED;
            }
            boolean passwordAcceptable = Validator.isValidLoginPassword(password);

            // 2. Look up the account.
            User user = sqlite.getUser(username);
            if (user == null) {
                PasswordUtil.dummyVerify(password);
                AuditLogger.authFail(username, "unknown username");
                return DENIED;
            }

            // 3. Check the password. This runs for a disabled account too.
            boolean passwordCorrect;
            if (passwordAcceptable) {
                passwordCorrect = PasswordUtil.verify(password, user.getPassword());
            } else {
                PasswordUtil.dummyVerify(null);
                passwordCorrect = false;
                AuditLogger.validationFail(username, "login password", "length out of range");
            }

            // 4. A disabled account is refused even with the correct password.
            boolean disabled = user.getRole() == SQLite.ROLE_DISABLED || user.getLocked() != 0;
            if (disabled) {
                sqlite.recordFailedLogin(username, SQLite.now(), 0);
                AuditLogger.authFail(username, "attempt on disabled account");
                return DENIED;
            }

            // 5. Wrong password: count it and lock the account at the limit.
            if (!passwordCorrect) {
                int attempts = sqlite.recordFailedLogin(username, SQLite.now(), MAX_FAILED_ATTEMPTS);
                AuditLogger.authFail(username, "wrong password (failed attempt " + attempts + " of " + MAX_FAILED_ATTEMPTS + ")");
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    AuditLogger.lockout(username, attempts);
                }
                return DENIED;
            }

            // 6. Correct password. The role must still be an active one.
            if (user.getRole() < SQLite.ROLE_CLIENT || user.getRole() > SQLite.ROLE_ADMIN) {
                AuditLogger.authFail(username, "account has no valid role");
                return DENIED;
            }
            if (!sqlite.recordSuccessfulLogin(username, SQLite.now())) {
                AuditLogger.authFail(username, "login could not be recorded");
                return DENIED;
            }
            if (!Session.start(user)) {
                AuditLogger.authFail(username, "session could not be started");
                return DENIED;
            }
            AuditLogger.authSuccess(username);
            result = new LoginResult(true, user.getLastAttemptTs(), user.getLastAttemptStatus());
        } catch (Exception ex) {
            Session.end();
            result = DENIED;
        } finally {
            PasswordUtil.wipe(password);
        }
        return result;
    }

    /**
     * Checks the password of the logged-in user again, right before a
     * critical operation.
     *
     * A wrong password counts as a failed login: it is logged, it adds 1 to
     * the failed-login counter and the fifth consecutive failure disables
     * the account and ends the session. A correct password resets the
     * counter.
     */
    public static synchronized boolean reauthenticate(char[] password) {
        boolean confirmed = false;
        try {
            if (sqlite == null || !Session.isActive()) {
                return false;
            }
            String username = Session.getUsername();
            User user = sqlite.getUser(username);
            if (user == null || user.getRole() != Session.getRole() || user.getLocked() != 0) {
                PasswordUtil.dummyVerify(password);
                Session.end();
                AuditLogger.authFail(username, "re-authentication on an invalid session");
                return false;
            }
            boolean correct = Validator.isValidLoginPassword(password) && PasswordUtil.verify(password, user.getPassword());
            if (!correct) {
                int attempts = sqlite.recordFailedLogin(username, SQLite.now(), MAX_FAILED_ATTEMPTS);
                AuditLogger.authFail(username, "re-authentication failed (failed attempt " + attempts + " of " + MAX_FAILED_ATTEMPTS + ")");
                if (attempts >= MAX_FAILED_ATTEMPTS) {
                    AuditLogger.lockout(username, attempts);
                    Session.end();
                }
                return false;
            }
            if (!sqlite.resetFailedAttempts(username)) {
                return false;
            }
            AuditLogger.log(AuditLogger.AUTH_SUCCESS, username, "Re-authentication successful");
            confirmed = true;
        } catch (Exception ex) {
            confirmed = false;
        } finally {
            PasswordUtil.wipe(password);
        }
        return confirmed;
    }

    /** Ends the session and records the logout. */
    public static synchronized void logout() {
        try {
            if (Session.isActive()) {
                AuditLogger.logout(Session.getUsername());
            }
        } catch (Exception ex) {
            // The session is ended below in every case.
        } finally {
            Session.end();
        }
    }
}
