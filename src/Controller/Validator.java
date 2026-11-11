package Controller;

import java.util.regex.Pattern;

/**
 * Input validation for every field of the application.
 *
 * Policy: reject by default. Each method only answers "valid" or "not valid".
 * No method trims, escapes, converts or otherwise repairs the input. A value
 * that fails is rejected as a whole and the caller must stop the action.
 *
 * Each check tests null and length first, then matches the whole value
 * against a whitelist pattern. The parse methods return null for anything
 * that is not valid, so a caller can never use a rejected value by accident.
 */
public final class Validator {

    public static final int USERNAME_MIN = 4;
    public static final int USERNAME_MAX = 20;
    public static final int PASSWORD_MIN = 8;
    public static final int PASSWORD_MAX = 64;
    public static final int PRODUCT_NAME_MAX = 50;
    public static final int SEARCH_MAX = 50;
    public static final int ROLE_MIN = 1;
    public static final int ROLE_MAX = 5;
    public static final int STOCK_MIN = 0;
    public static final int STOCK_MAX = 10000;
    public static final double PRICE_MAX = 1000000.00;

    // Letters and digits only.
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9]{4,20}");
    // Letters, digits and single inner spaces. Must start and end with a letter or digit.
    private static final Pattern PRODUCT_NAME = Pattern.compile("[A-Za-z0-9]+( [A-Za-z0-9]+)*");
    private static final Pattern SEARCH = Pattern.compile("[A-Za-z0-9]+( [A-Za-z0-9]+)*");
    private static final Pattern ROLE = Pattern.compile("[1-5]");
    // Whole number without sign, at most 5 digits.
    private static final Pattern WHOLE_NUMBER = Pattern.compile("[0-9]{1,5}");
    // Up to 7 digits, optionally followed by a dot and 1 or 2 decimals.
    private static final Pattern PRICE = Pattern.compile("[0-9]{1,7}(\\.[0-9]{1,2})?");

    private Validator() {
    }

    /* ---------------- Text fields ---------------- */

    /** 4 to 20 characters, letters and digits only. */
    public static boolean isValidUsername(String username) {
        if (username == null || username.length() < USERNAME_MIN || username.length() > USERNAME_MAX) {
            return false;
        }
        return USERNAME.matcher(username).matches();
    }

    /** 1 to 50 characters: letters, digits and single spaces between words. */
    public static boolean isValidProductName(String name) {
        if (name == null || name.isEmpty() || name.length() > PRODUCT_NAME_MAX) {
            return false;
        }
        return PRODUCT_NAME.matcher(name).matches();
    }

    /** 1 to 50 characters: letters, digits and single spaces between words. */
    public static boolean isValidSearch(String text) {
        if (text == null || text.isEmpty() || text.length() > SEARCH_MAX) {
            return false;
        }
        return SEARCH.matcher(text).matches();
    }

    /* ---------------- Passwords ---------------- */

    /**
     * Password policy: 8 to 64 characters, with at least one uppercase
     * letter, one lowercase letter, one digit and one symbol. Only printable
     * ASCII characters without spaces are allowed; any other character
     * rejects the whole password.
     */
    public static boolean isValidPassword(char[] password) {
        if (password == null || password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
            return false;
        }
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;
        for (int i = 0; i < password.length; i++) {
            char c = password[i];
            if (c >= 'A' && c <= 'Z') {
                upper = true;
            } else if (c >= 'a' && c <= 'z') {
                lower = true;
            } else if (c >= '0' && c <= '9') {
                digit = true;
            } else if (c > ' ' && c <= '~') {
                symbol = true;
            } else {
                return false;
            }
        }
        return upper && lower && digit && symbol;
    }

    /**
     * Length check only, for the password typed at login. The full policy is
     * not applied there, so the login screen does not reveal the policy and
     * an over-long value is rejected before any hashing is done.
     */
    public static boolean isValidLoginPassword(char[] password) {
        return password != null && password.length >= 1 && password.length <= PASSWORD_MAX;
    }

    /** True when both entries are present and identical. */
    public static boolean passwordsMatch(char[] password, char[] confirmation) {
        if (password == null || confirmation == null || password.length != confirmation.length) {
            return false;
        }
        int difference = 0;
        for (int i = 0; i < password.length; i++) {
            difference |= password[i] ^ confirmation[i];
        }
        return difference == 0;
    }

    /* ---------------- Numbers ---------------- */

    /** Role code 1 to 5. */
    public static boolean isValidRole(int role) {
        return role >= ROLE_MIN && role <= ROLE_MAX;
    }

    /** Returns the role code (1 to 5), or null when the text is not one. */
    public static Integer parseRole(String text) {
        if (text == null || text.length() != 1 || !ROLE.matcher(text).matches()) {
            return null;
        }
        return Integer.valueOf(text.charAt(0) - '0');
    }

    /** Returns the stock (0 to 10,000), or null when the text is not valid. */
    public static Integer parseStock(String text) {
        Integer value = parseWholeNumber(text);
        if (value == null || value < STOCK_MIN || value > STOCK_MAX) {
            return null;
        }
        return value;
    }

    /**
     * Returns the purchase quantity, or null when the text is not valid.
     * A quantity must be at least 1 and at most the stock that is available.
     */
    public static Integer parseQuantity(String text, int available) {
        Integer value = parseWholeNumber(text);
        if (value == null || value < 1 || value > available || value > STOCK_MAX) {
            return null;
        }
        return value;
    }

    /**
     * Returns the price, or null when the text is not valid. A price is a
     * plain decimal number with at most 2 decimals, above 0 and at most
     * 1,000,000.00.
     */
    public static Double parsePrice(String text) {
        if (text == null || text.isEmpty() || text.length() > 10 || !PRICE.matcher(text).matches()) {
            return null;
        }
        try {
            double value = Double.parseDouble(text);
            if (value <= 0.0 || value > PRICE_MAX) {
                return null;
            }
            return Double.valueOf(value);
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    private static Integer parseWholeNumber(String text) {
        if (text == null || text.isEmpty() || text.length() > 5 || !WHOLE_NUMBER.matcher(text).matches()) {
            return null;
        }
        try {
            return Integer.valueOf(Integer.parseInt(text));
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
