import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class PasswordGenerator {

    private static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String CHAR_UPPER = CHAR_LOWER.toUpperCase();
    private static final String NUMBER = "0123456789";
    private static final String SPECIAL_CHAR = "!@#$%^&*()_-+=<>?";

    private static final SecureRandom random = new SecureRandom();
    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("Welcome to the Secure Password Generator!");

        System.out.print("Enter desired password length: ");
        int length = scanner.nextInt();

        System.out.print("Include uppercase letters? (yes/no): ");
        boolean includeUpper = scanner.next().equalsIgnoreCase("yes");

        System.out.print("Include lowercase letters? (yes/no): ");
        boolean includeLower = scanner.next().equalsIgnoreCase("yes");

        System.out.print("Include numbers? (yes/no): ");
        boolean includeNumbers = scanner.next().equalsIgnoreCase("yes");

        System.out.print("Include special characters? (yes/no): ");
        boolean includeSpecial = scanner.next().equalsIgnoreCase("yes");

        String password = generatePassword(length, includeUpper, includeLower, includeNumbers, includeSpecial);
        System.out.println("Generated Password: " + password);

        System.out.print("Would you like to save this password in encrypted form? (yes/no): ");
        if (scanner.next().equalsIgnoreCase("yes")) {
            try {
                SecretKey secretKey = generateSecretKey();
                String encryptedPassword = encryptPassword(password, secretKey);
                System.out.println("Encrypted Password: " + encryptedPassword);

                // Decrypt the password to demonstrate the functionality
                String decryptedPassword = decryptPassword(encryptedPassword, secretKey);
                System.out.println("Decrypted Password: " + decryptedPassword);

            } catch (Exception e) {
                System.err.println("Error during encryption/decryption: " + e.getMessage());
            }
        }
    }

    private static String generatePassword(int length, boolean includeUpper, boolean includeLower, boolean includeNumbers, boolean includeSpecial) {
        StringBuilder passwordChars = new StringBuilder();
        
        if (includeUpper) {
            passwordChars.append(CHAR_UPPER);
        }
        if (includeLower) {
            passwordChars.append(CHAR_LOWER);
        }
        if (includeNumbers) {
            passwordChars.append(NUMBER);
        }
        if (includeSpecial) {
            passwordChars.append(SPECIAL_CHAR);
        }

        if (passwordChars.length() == 0) {
            throw new IllegalArgumentException("At least one character type should be selected");
        }

        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(passwordChars.charAt(random.nextInt(passwordChars.length())));
        }
        
        return password.toString();
    }

    private static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private static String encryptPassword(String password, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private static String decryptPassword(String encryptedPassword, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
        return new String(decryptedBytes);
    }
}
