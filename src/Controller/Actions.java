package Controller;

import Controller.AccessControl.Permission;
import Model.History;
import Model.Logs;
import Model.Product;
import Model.User;
import java.util.ArrayList;

/**
 * Every operation behind the management panels (products, purchase history,
 * users and logs).
 *
 * Each operation follows the same order:
 *   1. access check through AccessControl (denied by default, denial logged);
 *   2. input validation through Validator (a value that fails is rejected as
 *      a whole and the failure is logged; nothing is corrected);
 *   3. re-authentication for the critical operations (the administrator's
 *      own password is checked again);
 *   4. the database change;
 *   5. an audit log entry.
 *
 * No method throws. Any unexpected error is answered with a generic failure
 * message and nothing is changed. Password arrays are overwritten with zeros
 * before a method returns.
 */
public final class Actions {

    /** Outcome of an operation, with the message shown to the user. */
    public static final class Result {

        private final boolean ok;
        private final String message;

        private Result(boolean ok, String message) {
            this.ok = ok;
            this.message = message;
        }

        public boolean isOk() {
            return ok;
        }

        public String getMessage() {
            return message;
        }
    }

    public static final String MSG_DENIED = "You are not allowed to perform this action.";
    public static final String MSG_REAUTH = "Re-authentication failed. The action was cancelled.";
    public static final String MSG_FAILED = "The action could not be completed. Please try again.";
    public static final String MSG_PRODUCT_NAME = "Invalid product name. Use 1 to " + Validator.PRODUCT_NAME_MAX
        + " letters and digits, with single spaces between words.";
    public static final String MSG_STOCK = "Invalid stock. Enter a whole number from " + Validator.STOCK_MIN
        + " to " + Validator.STOCK_MAX + ".";
    public static final String MSG_PRICE = "Invalid price. Enter a number above 0 and up to 1000000,"
        + " with at most 2 decimal places.";
    public static final String MSG_QUANTITY = "Invalid quantity. Enter a whole number from 1 up to the available stock.";
    public static final String MSG_SEARCH = "Invalid search text. Use 1 to " + Validator.SEARCH_MAX
        + " letters and digits, with single spaces between words.";
    public static final String MSG_ROLE = "Invalid role.";
    public static final String MSG_PASSWORD = "Password must be " + Validator.PASSWORD_MIN + " to " + Validator.PASSWORD_MAX
        + " characters long and contain at least one uppercase letter, one lowercase letter,"
        + " one digit and one symbol. Spaces are not allowed.";
    public static final String MSG_MISMATCH = "The passwords do not match.";

    private static final Result DENIED = new Result(false, MSG_DENIED);
    private static final Result REAUTH = new Result(false, MSG_REAUTH);
    private static final Result FAILED = new Result(false, MSG_FAILED);

    private static SQLite sqlite = null;

    private Actions() {
    }

    public static synchronized void init(SQLite database) {
        sqlite = database;
    }

    private static Result ok(String message) {
        return new Result(true, message);
    }

    private static Result invalid(String field, String rule, String message) {
        AuditLogger.validationFail(Session.getUsername(), field, rule);
        return new Result(false, message);
    }

    /* ====================================================================
     * Products
     * ==================================================================== */

    /** Products for the product table. Empty when the user may not see them. */
    public static synchronized ArrayList<Product> listProducts() {
        try {
            if (sqlite != null && AccessControl.authorize(Permission.VIEW_PRODUCTS)) {
                return sqlite.getProduct();
            }
        } catch (Exception ex) {
            // Falls through to the empty list.
        }
        return new ArrayList<Product>();
    }

    public static synchronized Result purchase(String productName, String quantityText) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.PURCHASE_PRODUCT)) {
                return DENIED;
            }
            if (!Validator.isValidProductName(productName)) {
                return invalid("purchase product", "not a valid product name", MSG_PRODUCT_NAME);
            }
            Product product = sqlite.getProduct(productName);
            if (product == null) {
                return FAILED;
            }
            Integer quantity = Validator.parseQuantity(quantityText, product.getStock());
            if (quantity == null) {
                return invalid("purchase quantity", "must be a whole number from 1 to the available stock", MSG_QUANTITY);
            }
            String username = Session.getUsername();
            if (!sqlite.purchaseProduct(username, productName, quantity.intValue(), SQLite.now())) {
                return FAILED;
            }
            AuditLogger.purchase(username, "Purchased " + quantity + " x " + productName);
            return ok("Purchase successful.");
        } catch (Exception ex) {
            return FAILED;
        }
    }

    public static synchronized Result addProduct(String name, String stockText, String priceText) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.ADD_PRODUCT)) {
                return DENIED;
            }
            if (!Validator.isValidProductName(name)) {
                return invalid("product name", "must be 1-50 letters, digits and single spaces", MSG_PRODUCT_NAME);
            }
            Integer stock = Validator.parseStock(stockText);
            if (stock == null) {
                return invalid("product stock", "must be a whole number from 0 to 10000", MSG_STOCK);
            }
            Double price = Validator.parsePrice(priceText);
            if (price == null) {
                return invalid("product price", "must be above 0, at most 1000000, with up to 2 decimals", MSG_PRICE);
            }
            if (sqlite.getProduct(name) != null || !sqlite.addProduct(name, stock.intValue(), price.doubleValue())) {
                return FAILED;
            }
            AuditLogger.productMgmt(Session.getUsername(), "Added product " + name);
            return ok("Product added.");
        } catch (Exception ex) {
            return FAILED;
        }
    }

    public static synchronized Result editProduct(String currentName, String newName, String stockText, String priceText) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.EDIT_PRODUCT)) {
                return DENIED;
            }
            if (!Validator.isValidProductName(currentName)) {
                return invalid("product to edit", "not a valid product name", MSG_PRODUCT_NAME);
            }
            if (!Validator.isValidProductName(newName)) {
                return invalid("product name", "must be 1-50 letters, digits and single spaces", MSG_PRODUCT_NAME);
            }
            Integer stock = Validator.parseStock(stockText);
            if (stock == null) {
                return invalid("product stock", "must be a whole number from 0 to 10000", MSG_STOCK);
            }
            Double price = Validator.parsePrice(priceText);
            if (price == null) {
                return invalid("product price", "must be above 0, at most 1000000, with up to 2 decimals", MSG_PRICE);
            }
            if (!sqlite.updateProduct(currentName, newName, stock.intValue(), price.doubleValue())) {
                return FAILED;
            }
            AuditLogger.productMgmt(Session.getUsername(), "Edited product " + currentName
                + (currentName.equals(newName) ? "" : " (renamed to " + newName + ")"));
            return ok("Product updated.");
        } catch (Exception ex) {
            return FAILED;
        }
    }

    public static synchronized Result deleteProduct(String name) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.DELETE_PRODUCT)) {
                return DENIED;
            }
            if (!Validator.isValidProductName(name)) {
                return invalid("product to delete", "not a valid product name", MSG_PRODUCT_NAME);
            }
            if (!sqlite.removeProduct(name)) {
                return FAILED;
            }
            AuditLogger.productMgmt(Session.getUsername(), "Deleted product " + name);
            return ok("Product deleted.");
        } catch (Exception ex) {
            return FAILED;
        }
    }

    /* ====================================================================
     * Purchase history
     * ==================================================================== */

    /**
     * The purchase history the logged-in user may see: every purchase for a
     * role with VIEW_ALL_HISTORY, only the user's own purchases for a role
     * with VIEW_OWN_HISTORY, nothing otherwise.
     */
    private static ArrayList<History> permittedHistory() {
        if (sqlite == null || !Session.isActive()) {
            AccessControl.authorize(Permission.VIEW_OWN_HISTORY);
            return new ArrayList<History>();
        }
        if (AccessControl.isAllowed(Session.getRole(), Permission.VIEW_ALL_HISTORY)) {
            if (AccessControl.authorize(Permission.VIEW_ALL_HISTORY)) {
                return sqlite.getHistory();
            }
            return new ArrayList<History>();
        }
        if (AccessControl.authorize(Permission.VIEW_OWN_HISTORY)) {
            return sqlite.getHistory(Session.getUsername());
        }
        return new ArrayList<History>();
    }

    /** One table row: username, product, quantity, price, total, timestamp. */
    private static Object[] historyRow(History history) {
        Product product = sqlite.getProduct(history.getName());
        Object price = "N/A";
        Object total = "N/A";
        if (product != null) {
            price = product.getPrice();
            total = product.getPrice() * history.getStock();
        }
        return new Object[]{history.getUsername(), history.getName(), history.getStock(), price, total, SQLite.format(history.getTimestamp())};
    }

    /** Rows for the history table. */
    public static synchronized ArrayList<Object[]> historyRows() {
        ArrayList<Object[]> rows = new ArrayList<Object[]>();
        try {
            ArrayList<History> histories = permittedHistory();
            for (int i = 0; i < histories.size(); i++) {
                rows.add(historyRow(histories.get(i)));
            }
        } catch (Exception ex) {
            return new ArrayList<Object[]>();
        }
        return rows;
    }

    /**
     * Rows of the permitted history whose username or product contains the
     * search text. Returns null when the search text is rejected.
     */
    public static synchronized ArrayList<Object[]> searchHistoryRows(String text) {
        ArrayList<Object[]> rows = new ArrayList<Object[]>();
        try {
            ArrayList<History> histories = permittedHistory();
            if (!Session.isActive()) {
                return rows;
            }
            if (!Validator.isValidSearch(text)) {
                AuditLogger.validationFail(Session.getUsername(), "history search", "must be 1-50 letters, digits and single spaces");
                return null;
            }
            String wanted = text.toLowerCase();
            for (int i = 0; i < histories.size(); i++) {
                History history = histories.get(i);
                if (history.getUsername().toLowerCase().contains(wanted) || history.getName().toLowerCase().contains(wanted)) {
                    rows.add(historyRow(history));
                }
            }
        } catch (Exception ex) {
            return new ArrayList<Object[]>();
        }
        return rows;
    }

    /* ====================================================================
     * Users
     * ==================================================================== */

    /**
     * Users for the user table. The password hash is left out, so it never
     * reaches the screen.
     */
    public static synchronized ArrayList<User> listUsers() {
        ArrayList<User> users = new ArrayList<User>();
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.VIEW_USERS)) {
                return users;
            }
            ArrayList<User> stored = sqlite.getUsers();
            for (int i = 0; i < stored.size(); i++) {
                User u = stored.get(i);
                users.add(new User(u.getId(), u.getUsername(), "", u.getRole(), u.getLocked(),
                        u.getFailedAttempts(), u.getLastAttemptTs(), u.getLastAttemptStatus(), u.getPrevRole()));
            }
        } catch (Exception ex) {
            return new ArrayList<User>();
        }
        return users;
    }

    /**
     * Access check for an action on another account, used before any dialog
     * is shown. The operation itself checks again.
     */
    public static synchronized boolean canActOnUser(Permission permission, String targetUsername) {
        try {
            return sqlite != null && AccessControl.authorizeUserAction(permission, targetUsername);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * The role to preselect when an administrator edits or re-enables an
     * account: the role held before the account was disabled when there is
     * one, otherwise the current role. Returns Client (2) when unknown.
     */
    public static synchronized int suggestedRole(String targetUsername) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.VIEW_USERS) || !Validator.isValidUsername(targetUsername)) {
                return SQLite.ROLE_CLIENT;
            }
            User target = sqlite.getUser(targetUsername);
            if (target == null) {
                return SQLite.ROLE_CLIENT;
            }
            if (target.getRole() == SQLite.ROLE_DISABLED) {
                int previous = target.getPrevRole();
                return (previous >= SQLite.ROLE_CLIENT && previous <= SQLite.ROLE_ADMIN) ? previous : SQLite.ROLE_CLIENT;
            }
            return Validator.isValidRole(target.getRole()) ? target.getRole() : SQLite.ROLE_CLIENT;
        } catch (Exception ex) {
            return SQLite.ROLE_CLIENT;
        }
    }

    /** Changes the role of an account (1 to 5). Role 1 disables the account. */
    public static synchronized Result changeRole(String target, String roleText, char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorizeUserAction(Permission.EDIT_USER_ROLE, target)) {
                return DENIED;
            }
            Integer role = Validator.parseRole(roleText);
            if (role == null) {
                return invalid("user role", "must be a role code from 1 to 5", MSG_ROLE);
            }
            User before = sqlite.getUser(target);
            if (before == null) {
                return FAILED;
            }
            if (before.getRole() == role.intValue()) {
                return ok("The account already has that role.");
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            if (!sqlite.updateUserRole(target, role.intValue())) {
                return FAILED;
            }
            String actor = Session.getUsername();
            if (role.intValue() == SQLite.ROLE_DISABLED) {
                AuditLogger.userMgmt(actor, actor + " disabled " + target + " (was role " + before.getRole() + ")");
            } else if (before.getRole() == SQLite.ROLE_DISABLED) {
                AuditLogger.userMgmt(actor, actor + " re-enabled " + target + " as role " + role);
            } else {
                AuditLogger.userMgmt(actor, actor + " changed the role of " + target + " from " + before.getRole() + " to " + role);
            }
            return ok("Role updated.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(ownPassword);
        }
    }

    /** Disables an account (role 1, locked) and remembers its role. */
    public static synchronized Result lockUser(String target, char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorizeUserAction(Permission.LOCK_USER, target)) {
                return DENIED;
            }
            User before = sqlite.getUser(target);
            if (before == null) {
                return FAILED;
            }
            if (before.getRole() == SQLite.ROLE_DISABLED) {
                return ok("The account is already locked.");
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            if (!sqlite.disableUser(target)) {
                return FAILED;
            }
            String actor = Session.getUsername();
            AuditLogger.userMgmt(actor, actor + " locked " + target + " (was role " + before.getRole() + ")");
            return ok("Account locked.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(ownPassword);
        }
    }

    /**
     * Re-enables a disabled account with the role the administrator
     * confirmed (2 to 5) and resets its failed-login counter.
     */
    public static synchronized Result unlockUser(String target, String roleText, char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorizeUserAction(Permission.LOCK_USER, target)) {
                return DENIED;
            }
            Integer role = Validator.parseRole(roleText);
            if (role == null || role.intValue() == SQLite.ROLE_DISABLED) {
                return invalid("user role", "must be a role code from 2 to 5 to re-enable an account", MSG_ROLE);
            }
            User before = sqlite.getUser(target);
            if (before == null) {
                return FAILED;
            }
            if (before.getRole() != SQLite.ROLE_DISABLED) {
                return ok("The account is not locked.");
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            if (!sqlite.enableUser(target, role.intValue())) {
                return FAILED;
            }
            String actor = Session.getUsername();
            AuditLogger.userMgmt(actor, actor + " re-enabled " + target + " as role " + role);
            return ok("Account unlocked.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(ownPassword);
        }
    }

    public static synchronized Result deleteUser(String target, char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorizeUserAction(Permission.DELETE_USER, target)) {
                return DENIED;
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            if (!sqlite.removeUser(target)) {
                return FAILED;
            }
            String actor = Session.getUsername();
            AuditLogger.userMgmt(actor, actor + " deleted the account " + target);
            return ok("Account deleted.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(ownPassword);
        }
    }

    /**
     * Sets a new password for an account. The new password must meet the
     * password policy and is stored as a new salted hash.
     */
    public static synchronized Result changePassword(String target, char[] newPassword, char[] confirmation, char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorizeUserAction(Permission.CHANGE_USER_PASSWORD, target)) {
                return DENIED;
            }
            if (!Validator.isValidPassword(newPassword)) {
                return invalid("new password", "does not meet the password policy", MSG_PASSWORD);
            }
            if (!Validator.passwordsMatch(newPassword, confirmation)) {
                return invalid("new password", "confirmation does not match", MSG_MISMATCH);
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            String hash = PasswordUtil.hash(newPassword);
            if (hash == null || !sqlite.updateUserPassword(target, hash)) {
                return FAILED;
            }
            String actor = Session.getUsername();
            AuditLogger.userMgmt(actor, actor + " changed the password of " + target);
            return ok("Password changed.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(newPassword);
            PasswordUtil.wipe(confirmation);
            PasswordUtil.wipe(ownPassword);
        }
    }

    /* ====================================================================
     * Logs
     * ==================================================================== */

    /** Log entries for the log table. Empty when the user may not see them. */
    public static synchronized ArrayList<Logs> listLogs() {
        try {
            if (sqlite != null && AccessControl.authorize(Permission.VIEW_LOGS)) {
                return sqlite.getLogs();
            }
        } catch (Exception ex) {
            // Falls through to the empty list.
        }
        return new ArrayList<Logs>();
    }

    /** Deletes every log entry, then records who cleared the logs. */
    public static synchronized Result clearLogs(char[] ownPassword) {
        try {
            if (sqlite == null || !AccessControl.authorize(Permission.CLEAR_LOGS)) {
                return DENIED;
            }
            if (!AuthService.reauthenticate(ownPassword)) {
                return REAUTH;
            }
            if (!sqlite.clearLogs()) {
                return FAILED;
            }
            String actor = Session.getUsername();
            AuditLogger.logMgmt(actor, actor + " cleared the logs");
            return ok("Logs cleared.");
        } catch (Exception ex) {
            return FAILED;
        } finally {
            PasswordUtil.wipe(ownPassword);
        }
    }
}
