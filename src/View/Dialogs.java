package View;

import Controller.Actions;
import Controller.AuditLogger;
import java.awt.Component;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;

/**
 * Small dialogs shared by the management panels.
 * No dialog ever shows an exception, a stack trace or any other technical
 * detail.
 */
public final class Dialogs {

    public static final String GENERIC_ERROR = "An error occurred. Please try again.";

    private Dialogs() {
    }

    /**
     * Asks the logged-in user for their own password before a critical
     * operation. The input is masked.
     *
     * @return the password typed, or null when the dialog was cancelled
     */
    public static char[] askPassword(Component parent) {
        JPasswordField field = new JPasswordField();
        Object[] message = {"Enter your own password to confirm this action:", field};
        int result = JOptionPane.showConfirmDialog(parent, message, "CONFIRM IDENTITY",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null);
        char[] password = field.getPassword();
        field.setText("");
        if (result != JOptionPane.OK_OPTION) {
            java.util.Arrays.fill(password, '\0');
            return null;
        }
        return password;
    }

    /** Shows the outcome of an operation. */
    public static void show(Component parent, Actions.Result result, String title) {
        if (result == null) {
            error(parent, title);
            return;
        }
        JOptionPane.showMessageDialog(parent, result.getMessage(), title,
                result.isOk() ? JOptionPane.INFORMATION_MESSAGE : JOptionPane.WARNING_MESSAGE);
    }

    public static void warn(Component parent, String message, String title) {
        JOptionPane.showMessageDialog(parent, message, title, JOptionPane.WARNING_MESSAGE);
    }

    /**
     * Reports an unexpected failure with a generic message. The detail goes
     * to the logs as the name of the screen only.
     */
    public static void error(Component parent, String screen) {
        AuditLogger.error("Unexpected error in " + screen);
        JOptionPane.showMessageDialog(parent, GENERIC_ERROR, "ERROR", JOptionPane.ERROR_MESSAGE);
    }

    /** Sends the user to the login page when the session is no longer valid. */
    public static void enforceSession(Component component) {
        java.awt.Window window = SwingUtilities.getWindowAncestor(component);
        if (window instanceof Frame) {
            ((Frame) window).enforceSession();
        }
    }
}
