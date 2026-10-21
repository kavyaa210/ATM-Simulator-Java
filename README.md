# Console ATM (Java)

A beginner-friendly console ATM application written in Java. It supports account
registration and login, balance checks, deposits, withdrawals, PIN changes, and
a temporary lockout after repeated incorrect PIN attempts.

## Requirements

- Java JDK installed, with `java` and `javac` available in PowerShell.

This version stores account data locally in `atm_accounts.txt`; it does not use
MySQL or require a JDBC driver.

## Run

Open PowerShell in this project folder and run:

```powershell
javac ATM.java
java ATM
```

Choose **1** to register. New accounts start with a balance of **Rs. 0.00**.
After registration, choose **2** to log in.

## Local account data and security

The program creates `atm_accounts.txt` in the current working directory. It
stores usernames and balances alongside salted PIN hashes, not readable PINs.
The account file is ignored by Git so private local account data is not
published with the source code.

This is an educational console project, not banking software. File-based
storage does not provide the protections required for real financial accounts.
