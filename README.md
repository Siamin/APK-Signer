# APK Signer

A lightweight Python CLI tool for aligning, signing, and verifying Android APK files using a Java Keystore.

APK Signer uses Android SDK Build Tools and `keytool` to handle the signing process without requiring Android Studio.

## Features

- Automatically detects the Android SDK and available Build Tools.
- Supports **JKS** and **PKCS12** Keystore formats.
- Reads Keystore information automatically.
- Detects available aliases and identifies private key entries.
- Automatically selects the alias when only one private key is available.
- Displays certificate information, including:
  - Owner and Issuer
  - Signature algorithm
  - Public key algorithm
  - SHA-1 and SHA-256 fingerprints
  - Certificate validity period
- Aligns APK files using `zipalign`.
- Signs APK files using `apksigner`.
- Verifies the APK signature after signing.
- Keeps the original APK file unchanged.
- Uses secure password prompts instead of displaying passwords in the terminal.

## Requirements

- Python 3
- Java Development Kit (JDK)
- Android SDK
- Android SDK Build Tools

Required Android SDK tools:

- `zipalign`
- `apksigner`

`keytool` must also be available from your JDK installation.

## Installation

Clone the repository:

```bash
git clone https://github.com/Siamin/APK-Signer.git
cd APK-Signer
```

No additional Python packages are required.

Make sure Java and Android SDK Build Tools are installed and accessible.

## Usage

Run the script:

```bash
python3 apk_signer.py
```

Follow the terminal prompts:

1. Enter the APK file path.
2. Enter the Keystore file path.
3. Enter the Keystore password.
4. The tool reads the Keystore information and detects available aliases.
5. Select an alias if multiple private keys are available.
6. Enter the key password if required.
7. The APK is aligned and signed.
8. The resulting APK signature is verified.

## Output

By default, the signed APK is saved alongside the original APK with the `-signed` suffix.

Example:

```text
base.apk
base-signed.apk
```

The original APK is not modified.

## Security

- Passwords are requested securely through the terminal.
- Temporary password files are created with restricted permissions and should be removed after use.
- Never commit Keystore files (`.jks`, `.keystore`, `.p12`, `.pfx`) or passwords to Git.
- Keep your Keystore and its passwords in a secure backup location.

**Important:** Losing your Keystore or its private key may prevent you from publishing updates to an Android application signed with that key.

## Version

**Current version:** 1.2.0

## License

Add your preferred license before distributing or publishing this project.