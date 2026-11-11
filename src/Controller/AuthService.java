package Controller;

/**
 * Account registration (and, from the next step, login).
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
}
