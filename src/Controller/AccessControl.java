package Controller;

import Model.User;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * The single component that decides whether the logged-in user may do
 * something. Every screen and every action must ask here first.
 *
 * Design:
 *  - Default deny. A permission is granted only when the matrix below lists
 *    the role for it. An unknown role, a missing session or any error
 *    results in "denied".
 *  - The role is read again from the database on every check. A session
 *    whose account was deleted, disabled or changed is ended on the spot.
 *  - Every denial is written to the logs as ACCESS_DENIED.
 *
 * Hiding a button is not access control. Screens may use isAllowed() to
 * decide what to show, but each action must still call authorize().
 */
public final class AccessControl {

    public enum Permission {
        ACCESS_CLIENT_HOME,
        ACCESS_STAFF_HOME,
        ACCESS_MANAGER_HOME,
        ACCESS_ADMIN_HOME,
        VIEW_PRODUCTS,
        PURCHASE_PRODUCT,
        ADD_PRODUCT,
        EDIT_PRODUCT,
        DELETE_PRODUCT,
        VIEW_OWN_HISTORY,
        VIEW_ALL_HISTORY,
        VIEW_USERS,
        EDIT_USER_ROLE,
        LOCK_USER,
        DELETE_USER,
        CHANGE_USER_PASSWORD,
        VIEW_LOGS,
        CLEAR_LOGS
    }

    private static final Map<Permission, Set<Integer>> MATRIX = buildMatrix();

    private static SQLite sqlite = null;

    private AccessControl() {
    }

    /** The access control matrix: which roles hold each permission. */
    private static Map<Permission, Set<Integer>> buildMatrix() {
        Map<Permission, Set<Integer>> m = new EnumMap<Permission, Set<Integer>>(Permission.class);

        // Each role may open its own home panel only.
        m.put(Permission.ACCESS_CLIENT_HOME, roles(SQLite.ROLE_CLIENT));
        m.put(Permission.ACCESS_STAFF_HOME, roles(SQLite.ROLE_STAFF));
        m.put(Permission.ACCESS_MANAGER_HOME, roles(SQLite.ROLE_MANAGER));
        m.put(Permission.ACCESS_ADMIN_HOME, roles(SQLite.ROLE_ADMIN));

        // Client: purchase products and view own purchase history.
        // Staff: add, edit and delete products.
        // Manager: the same as Staff, plus the purchase history of all users.
        m.put(Permission.VIEW_PRODUCTS, roles(SQLite.ROLE_CLIENT, SQLite.ROLE_STAFF, SQLite.ROLE_MANAGER));
        m.put(Permission.PURCHASE_PRODUCT, roles(SQLite.ROLE_CLIENT));
        m.put(Permission.ADD_PRODUCT, roles(SQLite.ROLE_STAFF, SQLite.ROLE_MANAGER));
        m.put(Permission.EDIT_PRODUCT, roles(SQLite.ROLE_STAFF, SQLite.ROLE_MANAGER));
        m.put(Permission.DELETE_PRODUCT, roles(SQLite.ROLE_STAFF, SQLite.ROLE_MANAGER));
        m.put(Permission.VIEW_OWN_HISTORY, roles(SQLite.ROLE_CLIENT));
        m.put(Permission.VIEW_ALL_HISTORY, roles(SQLite.ROLE_MANAGER));

        // Admin: users and logs only. No product or history access.
        m.put(Permission.VIEW_USERS, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.EDIT_USER_ROLE, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.LOCK_USER, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.DELETE_USER, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.CHANGE_USER_PASSWORD, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.VIEW_LOGS, roles(SQLite.ROLE_ADMIN));
        m.put(Permission.CLEAR_LOGS, roles(SQLite.ROLE_ADMIN));

        return Collections.unmodifiableMap(m);
    }

    private static Set<Integer> roles(int... allowed) {
        Set<Integer> set = new HashSet<Integer>();
        for (int i = 0; i < allowed.length; i++) {
            set.add(Integer.valueOf(allowed[i]));
        }
        return Collections.unmodifiableSet(set);
    }

    public static synchronized void init(SQLite database) {
        sqlite = database;
    }

    /**
     * Pure matrix lookup with no logging and no session. Use it only to
     * decide which buttons to show. It is not an access check.
     */
    public static boolean isAllowed(int role, Permission permission) {
        try {
            if (permission == null) {
                return false;
            }
            Set<Integer> allowed = MATRIX.get(permission);
            return allowed != null && allowed.contains(Integer.valueOf(role));
        } catch (Exception ex) {
            return false;
        }
    }

    /** The home panel permission that belongs to a role, or null for none. */
    public static Permission homePermissionFor(int role) {
        switch (role) {
            case SQLite.ROLE_CLIENT:
                return Permission.ACCESS_CLIENT_HOME;
            case SQLite.ROLE_STAFF:
                return Permission.ACCESS_STAFF_HOME;
            case SQLite.ROLE_MANAGER:
                return Permission.ACCESS_MANAGER_HOME;
            case SQLite.ROLE_ADMIN:
                return Permission.ACCESS_ADMIN_HOME;
            default:
                return null;
        }
    }

    /**
     * The access check. Returns true only when a session is active, the
     * account still exists with the same active role in the database, and
     * the matrix grants the permission to that role.
     */
    public static synchronized boolean authorize(Permission permission) {
        boolean granted = false;
        try {
            String resource = (permission == null) ? "UNKNOWN" : permission.name();

            if (!Session.isActive()) {
                AuditLogger.accessDenied(null, 0, resource + " (no session)");
                return false;
            }
            String username = Session.getUsername();
            int sessionRole = Session.getRole();

            if (permission == null || sqlite == null) {
                AuditLogger.accessDenied(username, sessionRole, resource);
                return false;
            }

            // Confirm the session against the database.
            User current = sqlite.getUser(username);
            if (current == null || current.getRole() != sessionRole || current.getLocked() != 0) {
                Session.end();
                AuditLogger.accessDenied(username, sessionRole, resource + " (session no longer valid)");
                return false;
            }

            granted = isAllowed(sessionRole, permission);
            if (!granted) {
                AuditLogger.accessDenied(username, sessionRole, resource);
            }
        } catch (Exception ex) {
            granted = false;
        }
        return granted;
    }

    /**
     * The access check for an action on another account (edit role, lock,
     * delete, change password). On top of authorize() it applies these rules:
     *  - the target account must exist;
     *  - an administrator may change their own password, but may not edit
     *    the role of, lock or delete their own account;
     *  - an administrator may not act on another administrator's account.
     */
    public static synchronized boolean authorizeUserAction(Permission permission, String targetUsername) {
        try {
            if (!authorize(permission)) {
                return false;
            }
            String actor = Session.getUsername();
            int actorRole = Session.getRole();
            String resource = permission.name();

            if (targetUsername == null || !Validator.isValidUsername(targetUsername)) {
                AuditLogger.accessDenied(actor, actorRole, resource + " (invalid target)");
                return false;
            }
            User target = sqlite.getUser(targetUsername);
            if (target == null) {
                AuditLogger.accessDenied(actor, actorRole, resource + " (target not found)");
                return false;
            }
            if (targetUsername.equals(actor)) {
                if (permission == Permission.CHANGE_USER_PASSWORD) {
                    return true;
                }
                AuditLogger.accessDenied(actor, actorRole, resource + " on own account");
                return false;
            }
            if (target.getRole() == SQLite.ROLE_ADMIN) {
                AuditLogger.accessDenied(actor, actorRole, resource + " on another administrator");
                return false;
            }
            return true;
        } catch (Exception ex) {
            return false;
        }
    }
}
