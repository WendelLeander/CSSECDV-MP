package Controller;

import Model.History;
import Model.Logs;
import Model.Product;
import Model.User;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/**
 * Data access layer for database.db.
 *
 * Security notes:
 *  - Every query is a PreparedStatement with bound parameters. No SQL string
 *    is ever built from user input (blocks SQL injection).
 *  - No method prints an exception or stack trace. A failure is written to
 *    the logs table as an ERROR event (exception class name only) and the
 *    method returns a safe value: false, null, -1 or an empty list.
 *  - This class stores whatever password string it is given. Callers must
 *    pass a salted hash, never a plain-text password.
 */
public class SQLite {

    public static final int ROLE_DISABLED = 1;
    public static final int ROLE_CLIENT = 2;
    public static final int ROLE_STAFF = 3;
    public static final int ROLE_MANAGER = 4;
    public static final int ROLE_ADMIN = 5;

    public static final String STATUS_SUCCESS = "SUCCESS";
    public static final String STATUS_FAILED = "FAILED";

    String driverURL = "jdbc:sqlite:" + "database.db";

    // Guards against endless recursion when writing an ERROR log itself fails.
    private boolean reportingError = false;

    /* ====================================================================
     * Error handling
     * ==================================================================== */

    /**
     * Records a database failure without exposing it to the user.
     * Only the operation name and the exception class are stored. The
     * exception message is left out because it can contain SQL text.
     */
    private void reportError(String operation, Exception ex) {
        if (reportingError) {
            return;
        }
        reportingError = true;
        try {
            String type = (ex == null) ? "Unknown" : ex.getClass().getSimpleName();
            addLogs("ERROR", "SYSTEM", "Database operation failed: " + operation + " (" + type + ")",
                    now());
        } catch (Exception ignored) {
            // Nothing else can safely be done here.
        } finally {
            reportingError = false;
        }
    }

    /**
     * The current time as text, always with 3 millisecond digits
     * (yyyy-MM-dd HH:mm:ss.SSS). Every stored timestamp uses this format so
     * that it is read back and sorted correctly.
     */
    public static String now() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
    }

    /**
     * A stored time as text for the tables on screen, in the same fixed
     * format (yyyy-MM-dd HH:mm:ss.SSS). Returns an empty text for no time.
     */
    public static String format(Date time) {
        if (time == null) {
            return "";
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(time);
    }

    private Connection connect() throws Exception {
        return DriverManager.getConnection(driverURL);
    }

    private boolean isValidActiveRole(int role) {
        return role >= ROLE_CLIENT && role <= ROLE_ADMIN;
    }

    /** Runs a statement that has no parameters (schema statements only). */
    private boolean executeSchema(String operation, String sql) {
        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.execute();
            return true;
        } catch (Exception ex) {
            reportError(operation, ex);
            return false;
        }
    }

    /* ====================================================================
     * Schema
     * ==================================================================== */

    /**
     * Creates any missing table and adds the security columns to an older
     * users table. Safe to call on every start-up.
     */
    public boolean initSchema() {
        boolean ok = createHistoryTable();
        ok = createLogsTable() && ok;
        ok = createProductTable() && ok;
        ok = createUserTable() && ok;
        ok = addUserColumnIfMissing("failed_attempts", "INTEGER NOT NULL DEFAULT 0") && ok;
        ok = addUserColumnIfMissing("last_attempt_ts", "TEXT") && ok;
        ok = addUserColumnIfMissing("last_attempt_status", "TEXT") && ok;
        ok = addUserColumnIfMissing("prev_role", "INTEGER") && ok;
        return ok;
    }

    /**
     * Adds a column to the users table when it is not there yet.
     * Both arguments are fixed constants from initSchema(), never user input.
     */
    private boolean addUserColumnIfMissing(String column, String definition) {
        boolean exists = false;
        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement("PRAGMA table_info(users)");
            ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) {
                    exists = true;
                }
            }
        } catch (Exception ex) {
            reportError("addUserColumnIfMissing", ex);
            return false;
        }
        if (exists) {
            return true;
        }
        return executeSchema("addUserColumnIfMissing",
                "ALTER TABLE users ADD COLUMN " + column + " " + definition);
    }

    public boolean createNewDatabase() {
        try (Connection conn = connect()) {
            return conn != null;
        } catch (Exception ex) {
            reportError("createNewDatabase", ex);
            return false;
        }
    }

    public boolean createHistoryTable() {
        String sql = "CREATE TABLE IF NOT EXISTS history (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " username TEXT NOT NULL,\n"
            + " name TEXT NOT NULL,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";
        return executeSchema("createHistoryTable", sql);
    }

    public boolean createLogsTable() {
        String sql = "CREATE TABLE IF NOT EXISTS logs (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " event TEXT NOT NULL,\n"
            + " username TEXT NOT NULL,\n"
            + " desc TEXT NOT NULL,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";
        return executeSchema("createLogsTable", sql);
    }

    public boolean createProductTable() {
        String sql = "CREATE TABLE IF NOT EXISTS product (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " name TEXT NOT NULL UNIQUE,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " price REAL DEFAULT 0.00\n"
            + ");";
        return executeSchema("createProductTable", sql);
    }

    public boolean createUserTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " username TEXT NOT NULL UNIQUE,\n"
            + " password TEXT NOT NULL,\n"
            + " role INTEGER DEFAULT 2,\n"
            + " locked INTEGER DEFAULT 0,\n"
            + " failed_attempts INTEGER NOT NULL DEFAULT 0,\n"
            + " last_attempt_ts TEXT,\n"
            + " last_attempt_status TEXT,\n"
            + " prev_role INTEGER\n"
            + ");";
        return executeSchema("createUserTable", sql);
    }

    public boolean dropHistoryTable() {
        return executeSchema("dropHistoryTable", "DROP TABLE IF EXISTS history;");
    }

    public boolean dropLogsTable() {
        return executeSchema("dropLogsTable", "DROP TABLE IF EXISTS logs;");
    }

    public boolean dropProductTable() {
        return executeSchema("dropProductTable", "DROP TABLE IF EXISTS product;");
    }

    public boolean dropUserTable() {
        return executeSchema("dropUserTable", "DROP TABLE IF EXISTS users;");
    }

    /* ====================================================================
     * Logs
     * ==================================================================== */

    public boolean addLogs(String event, String username, String desc, String timestamp) {
        String sql = "INSERT INTO logs(event,username,desc,timestamp) VALUES(?,?,?,?)";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, event);
            pstmt.setString(2, username);
            pstmt.setString(3, desc);
            pstmt.setString(4, timestamp);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("addLogs", ex);
            return false;
        }
    }

    public ArrayList<Logs> getLogs() {
        String sql = "SELECT id, event, username, desc, timestamp FROM logs";
        ArrayList<Logs> logs = new ArrayList<Logs>();

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql);
            ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                logs.add(new Logs(rs.getInt("id"),
                                   rs.getString("event"),
                                   rs.getString("username"),
                                   rs.getString("desc"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            reportError("getLogs", ex);
            return new ArrayList<Logs>();
        }
        return logs;
    }

    public boolean clearLogs() {
        String sql = "DELETE FROM logs";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.executeUpdate();
            return true;
        } catch (Exception ex) {
            reportError("clearLogs", ex);
            return false;
        }
    }

    /* ====================================================================
     * Purchase history
     * ==================================================================== */

    public boolean addHistory(String username, String name, int stock, String timestamp) {
        String sql = "INSERT INTO history(username,name,stock,timestamp) VALUES(?,?,?,?)";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, name);
            pstmt.setInt(3, stock);
            pstmt.setString(4, timestamp);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("addHistory", ex);
            return false;
        }
    }

    /** Purchase history of every user. */
    public ArrayList<History> getHistory() {
        String sql = "SELECT id, username, name, stock, timestamp FROM history";
        ArrayList<History> histories = new ArrayList<History>();

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql);
            ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                histories.add(new History(rs.getInt("id"),
                                   rs.getString("username"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            reportError("getHistory", ex);
            return new ArrayList<History>();
        }
        return histories;
    }

    /** Purchase history of one user only (exact username match). */
    public ArrayList<History> getHistory(String username) {
        String sql = "SELECT id, username, name, stock, timestamp FROM history WHERE username = ?";
        ArrayList<History> histories = new ArrayList<History>();

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    histories.add(new History(rs.getInt("id"),
                                       rs.getString("username"),
                                       rs.getString("name"),
                                       rs.getInt("stock"),
                                       rs.getString("timestamp")));
                }
            }
        } catch (Exception ex) {
            reportError("getHistoryByUser", ex);
            return new ArrayList<History>();
        }
        return histories;
    }

    /* ====================================================================
     * Products
     * ==================================================================== */

    public boolean addProduct(String name, int stock, double price) {
        String sql = "INSERT INTO product(name,stock,price) VALUES(?,?,?)";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            pstmt.setInt(2, stock);
            pstmt.setDouble(3, price);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("addProduct", ex);
            return false;
        }
    }

    public ArrayList<Product> getProduct() {
        String sql = "SELECT id, name, stock, price FROM product";
        ArrayList<Product> products = new ArrayList<Product>();

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql);
            ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                products.add(new Product(rs.getInt("id"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getFloat("price")));
            }
        } catch (Exception ex) {
            reportError("getProducts", ex);
            return new ArrayList<Product>();
        }
        return products;
    }

    /** Returns the product with this exact name, or null when there is none. */
    public Product getProduct(String name) {
        String sql = "SELECT id, name, stock, price FROM product WHERE name = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return new Product(rs.getInt("id"),
                                       rs.getString("name"),
                                       rs.getInt("stock"),
                                       rs.getFloat("price"));
                }
            }
        } catch (Exception ex) {
            reportError("getProductByName", ex);
        }
        return null;
    }

    /**
     * Changes a product. When the name changes, the purchase history rows of
     * that product are renamed in the same transaction, so the history keeps
     * pointing at the product.
     */
    public boolean updateProduct(String currentName, String newName, int stock, double price) {
        String productSql = "UPDATE product SET name = ?, stock = ?, price = ? WHERE name = ?";
        String historySql = "UPDATE history SET name = ? WHERE name = ?";

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try (PreparedStatement product = conn.prepareStatement(productSql);
                PreparedStatement history = conn.prepareStatement(historySql)) {
                product.setString(1, newName);
                product.setInt(2, stock);
                product.setDouble(3, price);
                product.setString(4, currentName);
                if (product.executeUpdate() != 1) {
                    conn.rollback();
                    return false;
                }
                if (!currentName.equals(newName)) {
                    history.setString(1, newName);
                    history.setString(2, currentName);
                    history.executeUpdate();
                }
                conn.commit();
                return true;
            } catch (Exception ex) {
                conn.rollback();
                throw ex;
            }
        } catch (Exception ex) {
            reportError("updateProduct", ex);
            return false;
        }
    }

    public boolean removeProduct(String name) {
        String sql = "DELETE FROM product WHERE name = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, name);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("removeProduct", ex);
            return false;
        }
    }

    /**
     * Buys a product: lowers the stock and writes the history row in one
     * transaction, so either both happen or neither does. The stock check is
     * part of the UPDATE itself, so the stock can never go below zero.
     *
     * @return true only when the purchase was fully recorded
     */
    public boolean purchaseProduct(String username, String productName, int quantity, String timestamp) {
        if (quantity <= 0) {
            return false;
        }
        String updateSql = "UPDATE product SET stock = stock - ? WHERE name = ? AND stock >= ?";
        String insertSql = "INSERT INTO history(username,name,stock,timestamp) VALUES(?,?,?,?)";

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try (PreparedStatement update = conn.prepareStatement(updateSql);
                PreparedStatement insert = conn.prepareStatement(insertSql)) {
                update.setInt(1, quantity);
                update.setString(2, productName);
                update.setInt(3, quantity);
                if (update.executeUpdate() != 1) {
                    conn.rollback();
                    return false;
                }
                insert.setString(1, username);
                insert.setString(2, productName);
                insert.setInt(3, quantity);
                insert.setString(4, timestamp);
                if (insert.executeUpdate() != 1) {
                    conn.rollback();
                    return false;
                }
                conn.commit();
                return true;
            } catch (Exception ex) {
                conn.rollback();
                throw ex;
            }
        } catch (Exception ex) {
            reportError("purchaseProduct", ex);
            return false;
        }
    }

    /* ====================================================================
     * Users
     * ==================================================================== */

    private static final String USER_COLUMNS =
        "id, username, password, role, locked, failed_attempts, last_attempt_ts, last_attempt_status, prev_role";

    private User readUser(ResultSet rs) throws Exception {
        return new User(rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("password"),
                        rs.getInt("role"),
                        rs.getInt("locked"),
                        rs.getInt("failed_attempts"),
                        rs.getString("last_attempt_ts"),
                        rs.getString("last_attempt_status"),
                        rs.getInt("prev_role"));
    }

    /** Registers a user with the default Client role (2). */
    public boolean addUser(String username, String passwordHash) {
        return addUser(username, passwordHash, ROLE_CLIENT);
    }

    public boolean addUser(String username, String passwordHash, int role) {
        if (role < ROLE_DISABLED || role > ROLE_ADMIN) {
            return false;
        }
        String sql = "INSERT INTO users(username,password,role,locked) VALUES(?,?,?,?)";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, passwordHash);
            pstmt.setInt(3, role);
            pstmt.setInt(4, role == ROLE_DISABLED ? 1 : 0);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("addUser", ex);
            return false;
        }
    }

    public ArrayList<User> getUsers() {
        String sql = "SELECT " + USER_COLUMNS + " FROM users";
        ArrayList<User> users = new ArrayList<User>();

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql);
            ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                users.add(readUser(rs));
            }
        } catch (Exception ex) {
            reportError("getUsers", ex);
            return new ArrayList<User>();
        }
        return users;
    }

    /** Returns the user with this exact username, or null when there is none. */
    public User getUser(String username) {
        String sql = "SELECT " + USER_COLUMNS + " FROM users WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    return readUser(rs);
                }
            }
        } catch (Exception ex) {
            reportError("getUser", ex);
        }
        return null;
    }

    /**
     * True only when no account has this username, ignoring upper and lower
     * case, so "Admin" cannot be registered next to "admin". Any error
     * answers false, which makes the registration fail.
     */
    public boolean isUsernameAvailable(String username) {
        String sql = "SELECT COUNT(*) AS total FROM users WHERE username = ? COLLATE NOCASE";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                return rs.next() && rs.getInt("total") == 0;
            }
        } catch (Exception ex) {
            reportError("isUsernameAvailable", ex);
            return false;
        }
    }

    public boolean removeUser(String username) {
        String sql = "DELETE FROM users WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("removeUser", ex);
            return false;
        }
    }

    public boolean updateUserPassword(String username, String passwordHash) {
        String sql = "UPDATE users SET password = ? WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, passwordHash);
            pstmt.setString(2, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("updateUserPassword", ex);
            return false;
        }
    }

    /**
     * Disables an account: remembers its current role in prev_role, then sets
     * role = 1 and locked = 1 in a single statement so the two flags can
     * never disagree. An account that is already disabled is left as it is,
     * which keeps the remembered role from being overwritten with 1.
     *
     * @return true when the account exists and is disabled after the call
     */
    public boolean disableUser(String username) {
        String sql = "UPDATE users SET"
            + " prev_role = CASE WHEN role <> ? THEN role ELSE prev_role END,"
            + " role = ?, locked = 1"
            + " WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, ROLE_DISABLED);
            pstmt.setInt(2, ROLE_DISABLED);
            pstmt.setString(3, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("disableUser", ex);
            return false;
        }
    }

    /**
     * Re-enables an account with the role the administrator confirmed
     * (2 to 5 only), clears the locked flag and resets the failed-login
     * counter, all in a single statement.
     */
    public boolean enableUser(String username, int role) {
        if (!isValidActiveRole(role)) {
            return false;
        }
        String sql = "UPDATE users SET role = ?, locked = 0, failed_attempts = 0 WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, role);
            pstmt.setString(2, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("enableUser", ex);
            return false;
        }
    }

    /**
     * Changes a user's role (1 to 5). Role 1 goes through disableUser().
     * Roles 2 to 5 clear the locked flag, and the failed-login counter is
     * reset only when the account was disabled before the change.
     */
    public boolean updateUserRole(String username, int role) {
        if (role == ROLE_DISABLED) {
            return disableUser(username);
        }
        if (!isValidActiveRole(role)) {
            return false;
        }
        String sql = "UPDATE users SET"
            + " failed_attempts = CASE WHEN role = ? THEN 0 ELSE failed_attempts END,"
            + " role = ?, locked = 0"
            + " WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, ROLE_DISABLED);
            pstmt.setInt(2, role);
            pstmt.setString(3, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("updateUserRole", ex);
            return false;
        }
    }

    /**
     * Records a failed login for an existing account. In one transaction it
     * adds 1 to the failed-login counter, stores the attempt as the last
     * account use, and disables the account once the counter reaches
     * maxAttempts.
     *
     * @return the new counter value, or -1 when the account does not exist
     *         or the update failed
     */
    public int recordFailedLogin(String username, String timestamp, int maxAttempts) {
        String updateSql = "UPDATE users SET failed_attempts = failed_attempts + 1,"
            + " last_attempt_ts = ?, last_attempt_status = ? WHERE username = ?";
        String selectSql = "SELECT failed_attempts FROM users WHERE username = ?";
        String disableSql = "UPDATE users SET"
            + " prev_role = CASE WHEN role <> ? THEN role ELSE prev_role END,"
            + " role = ?, locked = 1"
            + " WHERE username = ?";

        try (Connection conn = connect()) {
            conn.setAutoCommit(false);
            try (PreparedStatement update = conn.prepareStatement(updateSql);
                PreparedStatement select = conn.prepareStatement(selectSql);
                PreparedStatement disable = conn.prepareStatement(disableSql)) {
                update.setString(1, timestamp);
                update.setString(2, STATUS_FAILED);
                update.setString(3, username);
                if (update.executeUpdate() != 1) {
                    conn.rollback();
                    return -1;
                }
                int attempts = -1;
                select.setString(1, username);
                try (ResultSet rs = select.executeQuery()) {
                    if (rs.next()) {
                        attempts = rs.getInt("failed_attempts");
                    }
                }
                if (attempts < 0) {
                    conn.rollback();
                    return -1;
                }
                if (maxAttempts > 0 && attempts >= maxAttempts) {
                    disable.setInt(1, ROLE_DISABLED);
                    disable.setInt(2, ROLE_DISABLED);
                    disable.setString(3, username);
                    disable.executeUpdate();
                }
                conn.commit();
                return attempts;
            } catch (Exception ex) {
                conn.rollback();
                throw ex;
            }
        } catch (Exception ex) {
            reportError("recordFailedLogin", ex);
            return -1;
        }
    }

    /** Sets the failed-login counter of an account back to 0. */
    public boolean resetFailedAttempts(String username) {
        String sql = "UPDATE users SET failed_attempts = 0 WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("resetFailedAttempts", ex);
            return false;
        }
    }

    /**
     * Records a successful login: resets the failed-login counter and stores
     * the attempt as the last account use. Read the previous last-use values
     * with getUser() before calling this.
     */
    public boolean recordSuccessfulLogin(String username, String timestamp) {
        String sql = "UPDATE users SET failed_attempts = 0,"
            + " last_attempt_ts = ?, last_attempt_status = ? WHERE username = ?";

        try (Connection conn = connect();
            PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, timestamp);
            pstmt.setString(2, STATUS_SUCCESS);
            pstmt.setString(3, username);
            return pstmt.executeUpdate() == 1;
        } catch (Exception ex) {
            reportError("recordSuccessfulLogin", ex);
            return false;
        }
    }
}
