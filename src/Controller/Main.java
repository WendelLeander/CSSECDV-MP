package Controller;


import View.Frame;



public class Main {
    
    public SQLite sqlite;
    
    public static void main(String[] args) {
        new Main().init();
    }
    
    public void init(){
        // Initialize a driver object
        sqlite = new SQLite();
        
        // Create any missing table and add the security columns if needed
        sqlite.initSchema();
        
        // Connect the security components to the database
        AuditLogger.init(sqlite);
        AccessControl.init(sqlite);
        AuthService.init(sqlite);
        
        // Initialize User Interface
        Frame frame = new Frame();
        frame.init(this);
    }
    
}
