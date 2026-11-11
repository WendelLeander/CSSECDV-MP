package Controller;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password hashing and verification.
 *
 * Algorithm: PBKDF2 with HMAC-SHA256, a random 16-byte salt per password,
 * 600,000 iterations and a 256-bit output. Only JDK classes are used, so no
 * extra library is needed.
 *
 * Stored format (one text value in users.password):
 *     pbkdf2_sha256:iterations:base64(salt):base64(hash)
 *
 * Every method fails closed: any error makes hash() return null and
 * verify() return false. Nothing is printed and nothing is thrown.
 */
public final class PasswordUtil {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String PREFIX = "pbkdf2_sha256";
    private static final int ITERATIONS = 600000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;

    // Limits accepted when reading a stored hash, so a corrupted or
    // tampered value cannot make the application hang.
    private static final int MIN_ITERATIONS = 100000;
    private static final int MAX_ITERATIONS = 5000000;
    private static final int MAX_STORED_LENGTH = 256;

    private static final SecureRandom RANDOM = new SecureRandom();

    // A valid hash of a random value nobody knows. Used by dummyVerify().
    private static String dummyHash = null;

    private PasswordUtil() {
    }

    /**
     * Hashes a password with a fresh random salt.
     *
     * @return the text to store in the database, or null when hashing failed
     */
    public static String hash(char[] password) {
        if (password == null) {
            return null;
        }
        try {
            byte[] salt = new byte[SALT_BYTES];
            RANDOM.nextBytes(salt);
            byte[] hash = pbkdf2(password, salt, ITERATIONS, HASH_BYTES);
            return PREFIX + ":" + ITERATIONS + ":"
                + Base64.getEncoder().encodeToString(salt) + ":"
                + Base64.getEncoder().encodeToString(hash);
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Checks a password against a stored hash.
     *
     * The hash is recomputed with the stored salt and iteration count, then
     * compared in constant time. A stored value that is not in the expected
     * format (for example an old plain-text password) never matches.
     */
    public static boolean verify(char[] password, String stored) {
        boolean matches = false;
        try {
            if (password == null || stored == null || stored.length() > MAX_STORED_LENGTH) {
                return false;
            }
            String[] parts = stored.split(":");
            if (parts.length != 4 || !PREFIX.equals(parts[0])) {
                return false;
            }
            int iterations = Integer.parseInt(parts[1]);
            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
                return false;
            }
            byte[] salt = Base64.getDecoder().decode(parts[2]);
            byte[] expected = Base64.getDecoder().decode(parts[3]);
            if (salt.length != SALT_BYTES || expected.length != HASH_BYTES) {
                return false;
            }
            byte[] actual = pbkdf2(password, salt, iterations, expected.length);
            matches = MessageDigest.isEqual(expected, actual);
        } catch (Exception ex) {
            matches = false;
        }
        return matches;
    }

    /**
     * Does the same amount of work as verify() and always returns false.
     * Call this when the username does not exist, so a failed login takes
     * about the same time whether or not the account exists.
     */
    public static boolean dummyVerify(char[] password) {
        try {
            String target = getDummyHash();
            if (target != null) {
                verify(password == null ? new char[0] : password, target);
            }
        } catch (Exception ex) {
            // Ignored on purpose: the answer is false either way.
        }
        return false;
    }

    /** Overwrites a password array with zeros once it is no longer needed. */
    public static void wipe(char[] password) {
        if (password != null) {
            Arrays.fill(password, '\0');
        }
    }

    private static synchronized String getDummyHash() {
        if (dummyHash == null) {
            byte[] random = new byte[24];
            RANDOM.nextBytes(random);
            dummyHash = hash(Base64.getEncoder().encodeToString(random).toCharArray());
        }
        return dummyHash;
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        try {
            return SecretKeyFactory.getInstance(ALGORITHM).generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
