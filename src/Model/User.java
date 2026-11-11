package Model;

public class User {
    private int id;
    private String username;
    private String password;
    private int role = 2;
    private int locked = 0;
    private int failedAttempts = 0;
    private String lastAttemptTs = null;
    private String lastAttemptStatus = null;
    private int prevRole = 0;

    public User(String username, String password){
        this.username = username;
        this.password = password;
    }
    
    public User(int id, String username, String password, int role, int locked){
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = role;
        this.locked = locked;
    }
    
    public User(int id, String username, String password, int role, int locked,
                int failedAttempts, String lastAttemptTs, String lastAttemptStatus, int prevRole){
        this(id, username, password, role, locked);
        this.failedAttempts = failedAttempts;
        this.lastAttemptTs = lastAttemptTs;
        this.lastAttemptStatus = lastAttemptStatus;
        this.prevRole = prevRole;
    }
    
    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public int getRole() {
        return role;
    }

    public void setRole(int role) {
        this.role = role;
    }

    public int getLocked() {
        return locked;
    }

    public void setLocked(int locked) {
        this.locked = locked;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public String getLastAttemptTs() {
        return lastAttemptTs;
    }

    public String getLastAttemptStatus() {
        return lastAttemptStatus;
    }

    /** Role held before the account was disabled; 0 when never disabled. */
    public int getPrevRole() {
        return prevRole;
    }
}
