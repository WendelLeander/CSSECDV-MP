package Controller;

import java.awt.Window;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

/**
 * Last line of defence for errors that no other code caught.
 *
 * It is registered as the default handler of every thread, including the
 * thread that runs the user interface. When an unhandled exception reaches
 * it, the handler:
 *   1. writes an ERROR entry to the logs (the exception class name only);
 *   2. ends the session at once;
 *   3. closes any open dialog and returns the window to the login page,
 *      which is the unprivileged state;
 *   4. shows one generic message.
 *
 * No stack trace, exception message or other technical detail is shown or
 * printed, and the application keeps running.
 */
public final class ErrorHandler implements Thread.UncaughtExceptionHandler {

    public static final String GENERIC_MESSAGE =
        "An unexpected error occurred. For your security you have been returned to the login page.";
    public static final String STARTUP_MESSAGE =
        "The application could not be started. Please contact the administrator.";

    private static final AtomicBoolean HANDLING = new AtomicBoolean(false);

    // Brings the user interface back to the login page. Set by Main.
    private static volatile Runnable safeState = null;

    private ErrorHandler() {
    }

    /** Registers the handler for every thread of the application. */
    public static void install() {
        Thread.setDefaultUncaughtExceptionHandler(new ErrorHandler());
    }

    /** Sets the action that returns the user interface to the login page. */
    public static void setSafeState(Runnable action) {
        safeState = action;
    }

    @Override
    public void uncaughtException(Thread thread, Throwable error) {
        // The session is ended first, whatever else happens.
        try {
            Session.end();
        } catch (Throwable ignored) {
        }

        // A second error raised while the first one is handled is not reported again.
        if (!HANDLING.compareAndSet(false, true)) {
            return;
        }
        try {
            String type = (error == null) ? "Unknown" : error.getClass().getSimpleName();
            AuditLogger.error("Unhandled error (" + type + "): session ended, user returned to the login page");
        } catch (Throwable ignored) {
        }

        Runnable recover = new Runnable() {
            @Override
            public void run() {
                try {
                    Window[] windows = Window.getWindows();
                    for (int i = 0; i < windows.length; i++) {
                        if (windows[i] instanceof JDialog && windows[i].isShowing()) {
                            windows[i].dispose();
                        }
                    }
                } catch (Throwable ignored) {
                }
                try {
                    Runnable action = safeState;
                    if (action != null) {
                        action.run();
                    }
                } catch (Throwable ignored) {
                }
                try {
                    JOptionPane.showMessageDialog(null, GENERIC_MESSAGE, "ERROR", JOptionPane.ERROR_MESSAGE);
                } catch (Throwable ignored) {
                } finally {
                    HANDLING.set(false);
                }
            }
        };

        try {
            if (SwingUtilities.isEventDispatchThread()) {
                recover.run();
            } else {
                SwingUtilities.invokeLater(recover);
            }
        } catch (Throwable ignored) {
            HANDLING.set(false);
        }
    }
}
