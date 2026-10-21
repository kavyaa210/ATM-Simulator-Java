import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class ATM {

    private static final int PIN_ATTEMPTS = 3;
    private static final int HASH_ITERATIONS = 120000;
    private static final int HASH_LENGTH = 256;
    private static final int SALT_LENGTH = 16;
    private static final long LOCKOUT_MILLIS = 60_000L;
    private static final String RESET = "\u001B[0m";
    private static final String CYAN = "\u001B[96m";
    private static final String BLUE = "\u001B[94m";
    private static final String GREEN = "\u001B[92m";
    private static final String YELLOW = "\u001B[93m";
    private static final String RED = "\u001B[91m";
    private static final String BOLD = "\u001B[1m";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final Path ACCOUNT_FILE = Paths.get("atm_accounts.txt");
    private static final String ACCOUNT_FILE_HEADER = "ATM_ACCOUNTS_V2";

    private static class Account {
        private final byte[] salt;
        private final byte[] pinHash;
        private BigDecimal balance;
        private int failedLoginAttempts;
        private long lockedUntilMillis;

        private Account(byte[] salt, byte[] pinHash, BigDecimal balance,
                int failedLoginAttempts, long lockedUntilMillis) {
            this.salt = salt;
            this.pinHash = pinHash;
            this.balance = balance;
            this.failedLoginAttempts = failedLoginAttempts;
            this.lockedUntilMillis = lockedUntilMillis;
        }
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        Map<String, Account> accounts = loadAccounts();
        try (Scanner scanner = new Scanner(System.in)) {
            printlnColored("==================================", CYAN);
            printlnColored("       WELCOME TO ATM", BOLD + CYAN);
            printlnColored("==================================", CYAN);

            String username = authenticate(accounts, scanner);
            if (username != null) {
                runAtm(accounts, scanner, username);
            }
        }
    }

    private static Map<String, Account> loadAccounts() throws IOException {
        Map<String, Account> accounts = new HashMap<>();
        if (!Files.exists(ACCOUNT_FILE)) {
            return accounts;
        }

        List<String> fileLines = Files.readAllLines(ACCOUNT_FILE, StandardCharsets.UTF_8);
        boolean readableUsernameFormat = !fileLines.isEmpty()
                && ACCOUNT_FILE_HEADER.equals(fileLines.get(0));
        int firstDataLine = readableUsernameFormat ? 1 : 0;
        for (int index = firstDataLine; index < fileLines.size(); index++) {
            String line = fileLines.get(index);
            int lineNumber = index + 1;
            if (line.trim().isEmpty()) {
                continue;
            }

            String[] fields = line.split("\\t", -1);
            if (fields.length != 4 && fields.length != 6) {
                throw new IOException("Invalid account data at line " + lineNumber
                        + " in " + ACCOUNT_FILE + ".");
            }

            try {
                String username = readableUsernameFormat
                        ? fields[0]
                        : new String(Base64.getUrlDecoder().decode(fields[0]),
                                StandardCharsets.UTF_8);
                byte[] salt = Base64.getDecoder().decode(fields[1]);
                byte[] pinHash = Base64.getDecoder().decode(fields[2]);
                BigDecimal balance = new BigDecimal(fields[3]);
                int failedLoginAttempts = fields.length == 6
                        ? Integer.parseInt(fields[4]) : 0;
                long lockedUntilMillis = fields.length == 6
                        ? Long.parseLong(fields[5]) : 0L;
                if (failedLoginAttempts < 0 || failedLoginAttempts >= PIN_ATTEMPTS
                        || lockedUntilMillis < 0) {
                    throw new IllegalArgumentException("Invalid login security data.");
                }
                accounts.put(username, new Account(salt, pinHash, balance,
                        failedLoginAttempts, lockedUntilMillis));
            } catch (IllegalArgumentException exception) {
                throw new IOException("Invalid account data at line " + lineNumber
                        + " in " + ACCOUNT_FILE + ".", exception);
            }
        }
        return accounts;
    }

    private static void saveAccounts(Map<String, Account> accounts) throws IOException {
        List<String> lines = new ArrayList<>();
        lines.add(ACCOUNT_FILE_HEADER);
        for (Map.Entry<String, Account> entry : accounts.entrySet()) {
            Account account = entry.getValue();
            lines.add(entry.getKey()
                    + "\t" + Base64.getEncoder().encodeToString(account.salt)
                    + "\t" + Base64.getEncoder().encodeToString(account.pinHash)
                    + "\t" + account.balance.toPlainString()
                    + "\t" + account.failedLoginAttempts
                    + "\t" + account.lockedUntilMillis);
        }

        Path absoluteFile = ACCOUNT_FILE.toAbsolutePath();
        Path temporaryFile = absoluteFile.resolveSibling(absoluteFile.getFileName() + ".tmp");
        Files.write(temporaryFile, lines, StandardCharsets.UTF_8);
        try {
            Files.move(temporaryFile, absoluteFile, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(temporaryFile, absoluteFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String authenticate(Map<String, Account> accounts, Scanner scanner)
            throws IOException, GeneralSecurityException {
        while (true) {
            printlnColored("\n1. Sign up", BLUE);
            printlnColored("2. Login", BLUE);
            printlnColored("3. Exit", BLUE);
            printColored("Choose an option: ", YELLOW);
            String choice = scanner.nextLine().trim();

            if ("1".equals(choice)) {
                if (register(accounts, scanner)) {
                    saveAccounts(accounts);
                    printlnColored("Account created. Please log in.", GREEN);
                }
            } else if ("2".equals(choice)) {
                String username = login(accounts, scanner);
                if (username != null) {
                    return username;
                }
            } else if ("3".equals(choice)) {
                printlnColored("Goodbye.", GREEN);
                return null;
            } else {
                printlnColored("Enter 1, 2, or 3.", RED);
            }
        }
    }

    private static boolean register(Map<String, Account> accounts, Scanner scanner)
            throws GeneralSecurityException {
        printColored("Create a username (up to 50 characters): ", YELLOW);
        String username = scanner.nextLine().trim();
        if (username.isEmpty() || username.length() > 50
                || username.chars().anyMatch(Character::isISOControl)) {
            printlnColored("Username must contain 1 to 50 printable characters.", RED);
            return false;
        }
        if (accounts.containsKey(username)) {
            printlnColored("Login already exists. Please choose a different username.", RED);
            return false;
        }

        printColored("Create your 4-digit PIN: ", YELLOW);
        String pin = scanner.nextLine().trim();
        if (!isValidPin(pin)) {
            printlnColored("PIN must contain exactly 4 digits.", RED);
            return false;
        }

        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        accounts.put(username, new Account(salt, hashPin(pin, salt),
                new BigDecimal("0.00"), 0, 0L));
        return true;
    }

    private static String login(Map<String, Account> accounts, Scanner scanner)
            throws IOException, GeneralSecurityException {
        printColored("Username: ", YELLOW);
        String username = scanner.nextLine().trim();

        for (int attempt = 1; attempt <= PIN_ATTEMPTS; attempt++) {
            Account account = accounts.get(username);
            if (account != null && account.lockedUntilMillis > System.currentTimeMillis()) {
                long remainingMillis = account.lockedUntilMillis - System.currentTimeMillis();
                long remainingSeconds = (remainingMillis + 999L) / 1000L;
                printlnColored("Account locked. Try again in "
                        + remainingSeconds + " seconds.", RED);
                return null;
            }
            if (account != null && account.lockedUntilMillis != 0L) {
                account.failedLoginAttempts = 0;
                account.lockedUntilMillis = 0L;
                saveAccounts(accounts);
            }

            printColored("Enter your 4-digit PIN: ", YELLOW);
            String pin = scanner.nextLine().trim();
            if (isValidPin(pin) && isValidLogin(accounts, username, pin)) {
                if (account != null && account.failedLoginAttempts != 0) {
                    account.failedLoginAttempts = 0;
                    saveAccounts(accounts);
                }
                printlnColored("\nLogin successful!", GREEN);
                return username;
            }
            printlnColored("Login error: incorrect username or PIN.", RED);

            if (account != null) {
                account.failedLoginAttempts++;
                if (account.failedLoginAttempts >= PIN_ATTEMPTS) {
                    account.failedLoginAttempts = 0;
                    account.lockedUntilMillis = System.currentTimeMillis() + LOCKOUT_MILLIS;
                    saveAccounts(accounts);
                    printlnColored(
                            "Too many incorrect attempts. Account locked for 60 seconds.",
                            RED
                    );
                    return null;
                }
                saveAccounts(accounts);
                if (attempt < PIN_ATTEMPTS) {
                    printlnColored("Attempts left: "
                            + (PIN_ATTEMPTS - account.failedLoginAttempts), YELLOW);
                }
            }
        }

        printlnColored("Access denied.", RED);
        return null;
    }

    private static boolean isValidLogin(
            Map<String, Account> accounts, String username, String pin
    ) throws GeneralSecurityException {
        Account account = accounts.get(username);
        if (account == null) {
            return false;
        }
        return MessageDigest.isEqual(account.pinHash, hashPin(pin, account.salt));
    }

    private static boolean isValidPin(String pin) {
        return pin.matches("\\d{4}");
    }

    private static byte[] hashPin(String pin, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec specification = new PBEKeySpec(
                pin.toCharArray(), salt, HASH_ITERATIONS, HASH_LENGTH
        );
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(specification).getEncoded();
        } finally {
            specification.clearPassword();
        }
    }

    private static void runAtm(
            Map<String, Account> accounts, Scanner scanner, String username
    ) throws IOException, GeneralSecurityException {
        Account account = accounts.get(username);
        boolean running = true;
        while (running) {
            printlnColored("\n========== ATM MENU ==========", BOLD + CYAN);
            printlnColored("1. Check Balance", BLUE);
            printlnColored("2. Deposit Money", BLUE);
            printlnColored("3. Withdraw Money", BLUE);
            printlnColored("4. Change PIN", BLUE);
            printlnColored("5. Exit", BLUE);
            printlnColored("==============================", CYAN);
            printColored("Enter your choice: ", YELLOW);

            String choice = scanner.nextLine().trim();
            switch (choice) {
                case "1":
                    showBalance(account);
                    break;
                case "2":
                    updateBalance(accounts, account, scanner, true);
                    break;
                case "3":
                    updateBalance(accounts, account, scanner, false);
                    break;
                case "4":
                    changePin(accounts, username, account, scanner);
                    break;
                case "5":
                    printlnColored("Thank you for using our ATM!", GREEN);
                    running = false;
                    break;
                default:
                    printlnColored("Enter a valid menu number.", RED);
            }
        }
    }

    private static void showBalance(Account account) {
        printfColored("Available Balance: Rs. %.2f%n", GREEN, account.balance);
    }

    private static void updateBalance(
            Map<String, Account> accounts, Account account, Scanner scanner, boolean deposit
    ) throws IOException {
        printColored(deposit ? "Enter deposit amount: Rs. "
                : "Enter withdrawal amount: Rs. ", YELLOW);
        BigDecimal amount;
        try {
            amount = new BigDecimal(scanner.nextLine().trim());
        } catch (NumberFormatException exception) {
            printlnColored("Invalid amount.", RED);
            return;
        }

        if (amount.compareTo(BigDecimal.ZERO) <= 0 || amount.scale() > 2) {
            printlnColored(
                    "Enter a positive amount with no more than 2 decimal places.", RED
            );
            return;
        }

        if (!deposit && amount.compareTo(account.balance) > 0) {
            printlnColored("Insufficient balance!", RED);
            return;
        }

        BigDecimal previousBalance = account.balance;
        account.balance = deposit
                ? account.balance.add(amount)
                : account.balance.subtract(amount);
        try {
            saveAccounts(accounts);
        } catch (IOException exception) {
            account.balance = previousBalance;
            throw exception;
        }

        if (deposit) {
            printlnColored("Deposit successful!", GREEN);
        } else {
            printlnColored("Please collect your cash.", GREEN);
        }
        showBalance(account);
    }

    private static void changePin(
            Map<String, Account> accounts, String username, Account account, Scanner scanner
    ) throws IOException, GeneralSecurityException {
        printColored("Enter current PIN: ", YELLOW);
        String oldPin = scanner.nextLine().trim();
        if (!isValidPin(oldPin)
                || !MessageDigest.isEqual(account.pinHash, hashPin(oldPin, account.salt))) {
            printlnColored("Incorrect current PIN!", RED);
            return;
        }

        printColored("Enter new 4-digit PIN: ", YELLOW);
        String newPin = scanner.nextLine().trim();
        if (!isValidPin(newPin)) {
            printlnColored("PIN must contain exactly 4 digits.", RED);
            return;
        }

        byte[] salt = new byte[SALT_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        Account updatedAccount = new Account(
                salt, hashPin(newPin, salt), account.balance, 0, 0L
        );
        accounts.put(username, updatedAccount);
        try {
            saveAccounts(accounts);
        } catch (IOException exception) {
            accounts.put(username, account);
            throw exception;
        }
        printlnColored("PIN changed successfully!", GREEN);
    }

    private static void printColored(String message, String color) {
        System.out.print(color + message + RESET);
    }

    private static void printlnColored(String message, String color) {
        System.out.println(color + message + RESET);
    }

    private static void printfColored(String format, String color, Object... values) {
        System.out.print(color);
        System.out.printf(format, values);
        System.out.print(RESET);
    }
}
