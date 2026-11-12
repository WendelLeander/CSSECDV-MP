package Controller;


import View.Frame;
import javax.swing.JOptionPane;



public class Main {
    
    public SQLite sqlite;
    
    public static void main(String[] args) {
        // From here on, an error nobody caught ends the session and brings
        // the user back to the login page with a generic message
        ErrorHandler.install();
        
        try {
            new Main().init();
        } catch (Throwable ex) {
            // The application could not start: show a generic message and stop
            AuditLogger.error("Application start-up failed");
            JOptionPane.showMessageDialog(null, ErrorHandler.STARTUP_MESSAGE, "ERROR", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
        }
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
        Actions.init(sqlite);
        
        // Initialize User Interface
        final Frame frame = new Frame();
        frame.init(this);
        
        // The safe state after an unhandled error is the login page
        ErrorHandler.setSafeState(new Runnable() {
            @Override
            public void run() {
                frame.forceLogin();
            }
        });
    }
    
}
