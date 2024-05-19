import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class PasswordGeneratorGUI extends JFrame {
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_+=<>?";
    private static final SecureRandom random = new SecureRandom();
    private static final String ALGORITHM = "AES";

    private JTextField lengthField;
    private JCheckBox specialCharsCheckbox;
    private JTextArea passwordArea;
    private SecretKey secretKey;

    public PasswordGeneratorGUI() {
        setTitle("Password Generator");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new GridLayout(5, 1));

        JLabel lengthLabel = new JLabel("Enter number of characters:");
        lengthField = new JTextField();
        specialCharsCheckbox = new JCheckBox("Use special characters");

        JButton generateButton = new JButton("Generate Password");
        generateButton.addActionListener(new GenerateButtonListener());

        passwordArea = new JTextArea();
        passwordArea.setLineWrap(true);
        passwordArea.setWrapStyleWord(true);
        passwordArea.setEditable(false);

        add(lengthLabel);
        add(lengthField);
        add(specialCharsCheckbox);
        add(generateButton);
        add(new JScrollPane(passwordArea));
    }

    private class GenerateButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            int length = Integer.parseInt(lengthField.getText());
            boolean useSpecialCharacters = specialCharsCheckbox.isSelected();

            try {
                String password = generatePassword(length, useSpecialCharacters);
                secretKey = generateKey();
                String encryptedPassword = encrypt(password, secretKey);
                passwordArea.setText("Generated Password: " + password + "\nEncrypted Password: " + encryptedPassword);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public static String generatePassword(int length, boolean useSpecialCharacters) {
        String characters = UPPERCASE + LOWERCASE + DIGITS;
        if (useSpecialCharacters) {
            characters += SPECIAL_CHARACTERS;
        }

        StringBuilder password = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(256); // AES-256
        return keyGen.generateKey();
    }

    public static String encrypt(String data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            PasswordGeneratorGUI frame = new PasswordGeneratorGUI();
            frame.setVisible(true);
        });
    }
}