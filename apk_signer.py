
import os
import re
import sys
import shutil
import getpass
import tempfile
import subprocess

from pathlib import Path


APP_NAME = "APK Signer"
VERSION = "1.2.0"


def header():
    print("\n" + "=" * 58)
    print(f"  {APP_NAME} v{VERSION}")
    print("  Android APK Signing Utility")
    print("=" * 58)


def natural_sort_key(value):
    return [
        int(x) if x.isdigit() else x.lower()
        for x in re.split(r"(\d+)", value)
    ]


def ask_file(title, extensions):
    while True:
        value = input(f"\n{title}: ").strip().strip('"')
        path = Path(value).expanduser()

        if not path.is_file():
            print("[!] File not found.")
            continue

        if path.suffix.lower() not in extensions:
            print("[!] Invalid file extension.")
            continue

        return path.resolve()


def find_android_tools():
    sdk_candidates = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        str(Path.home() / "Library/Android/sdk"),
        str(Path.home() / "Android/Sdk"),
    ]

    sdk = next(
        (
            Path(p).expanduser()
            for p in sdk_candidates
            if p and Path(p).expanduser().is_dir()
        ),
        None
    )

    if not sdk:
        raise RuntimeError("Android SDK not found.")

    build_tools = sdk / "build-tools"

    if not build_tools.is_dir():
        raise RuntimeError("Android Build Tools not found.")

    versions = sorted(
        [p for p in build_tools.iterdir() if p.is_dir()],
        key=lambda p: natural_sort_key(p.name)
    )

    for version in reversed(versions):
        apksigner = version / "apksigner"
        zipalign = version / "zipalign"

        if sys.platform == "win32":
            apksigner = apksigner.with_suffix(".bat")
            zipalign = zipalign.with_suffix(".exe")

        if apksigner.is_file() and zipalign.is_file():
            return apksigner, zipalign

    raise RuntimeError("No compatible Build Tools found.")


def find_keytool():
    java_home = os.environ.get("JAVA_HOME")

    candidates = []

    if java_home:
        candidates.append(Path(java_home) / "bin/keytool")

    found = shutil.which("keytool")

    if found:
        candidates.append(Path(found))

    for candidate in candidates:
        if sys.platform == "win32":
            candidate = candidate.with_suffix(".exe")

        if candidate.is_file():
            return candidate

    raise RuntimeError(
        "keytool not found. Install a JDK or configure JAVA_HOME."
    )


def create_secret_file(password):
    fd, filename = tempfile.mkstemp(prefix="apk_signer_secret_")

    try:
        os.chmod(filename, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(password)

        return Path(filename)

    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass

        Path(filename).unlink(missing_ok=True)
        raise


def run_command(command, title, show_output=True):
    print(f"\n[+] {title}")

    result = subprocess.run(
        [str(x) for x in command],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(error or f"{title} failed.")

    if show_output and result.stdout.strip():
        print(result.stdout.strip())

    print("[OK]")
    return result



def inspect_keystore(keytool, keystore, password_file):
    print("\n[+] Reading Keystore information...")

    result = run_command(
        [
            keytool,
            "-list",
            "-v",
            "-keystore",
            keystore,
            "-storepass:file",
            password_file
        ],
        "Validating Keystore",
        show_output=False
    )

    output = result.stdout

    # Detect Keystore type
    type_match = re.search(
        r"Keystore type:\s*(\S+)",
        output,
        re.IGNORECASE
    )

    if not type_match:
        raise RuntimeError("Could not detect Keystore type.")

    store_type = type_match.group(1).upper()

    if store_type not in ("JKS", "PKCS12"):
        raise RuntimeError(f"Unsupported Keystore type: {store_type}")

    # Extract individual entries
    entries = re.findall(
        r"(?ms)^Alias name:\s*(.*?)\s*\n(.*?)(?=^Alias name:|\Z)",
        output
    )

    private_keys = []

    print("\n" + "=" * 55)
    print("             KEYSTORE INFORMATION")
    print("=" * 55)

    print(f"\nKeystore Type: {store_type}")
    print(f"Total Entries: {len(entries)}")

    for alias, details in entries:
        entry_type = re.search(
            r"Entry type:\s*(.+)",
            details,
            re.IGNORECASE
        )

        if not entry_type:
            continue

        entry_type = entry_type.group(1).strip()

        if entry_type.lower() != "privatekeyentry":
            print(f"\n[!] Ignored non-private-key entry: {alias}")
            continue

        private_keys.append(alias.strip())

        def extract(pattern):
            match = re.search(
                pattern,
                details,
                re.IGNORECASE | re.MULTILINE
            )
            return match.group(1).strip() if match else "Unknown"

        print("\n" + "-" * 55)
        print(f"Alias: {alias.strip()}")
        print(f"Entry Type: {entry_type}")
        print(f"Creation Date: {extract(r'^Creation date:\s*(.+)$')}")
        print(f"Owner: {extract(r'^Owner:\s*(.+)$')}")
        print(f"Issuer: {extract(r'^Issuer:\s*(.+)$')}")
        print(
            f"Signature Algorithm: "
            f"{extract(r'^Signature algorithm name:\s*(.+)$')}"
        )
        print(
            f"Public Key Algorithm: "
            f"{extract(r'^Subject Public Key Algorithm:\s*(.+)$')}"
        )
        print(
            f"SHA-1: "
            f"{extract(r'^\s*SHA1:\s*(.+)$')}"
        )
        print(
            f"SHA-256: "
            f"{extract(r'^\s*SHA256:\s*(.+)$')}"
        )

        validity = re.search(
            r"Valid from:\s*(.+?)\s+until:\s*(.+)",
            details,
            re.IGNORECASE
        )

        if validity:
            print(f"Valid From: {validity.group(1).strip()}")
            print(f"Valid Until: {validity.group(2).strip()}")

    print("\n" + "=" * 55)
    print(f"Private Key Aliases Found: {len(private_keys)}")
    print("=" * 55)

    if not private_keys:
        raise RuntimeError(
            "No PrivateKeyEntry found in this Keystore."
        )

    return store_type, private_keys


def select_alias(aliases):
    if len(aliases) == 1:
        print(f"\n[+] Automatically selected Alias: {aliases[0]}")
        return aliases[0]

    while True:
        value = input("\nSelect Alias number: ").strip()

        if value.isdigit():
            index = int(value)

            if 1 <= index <= len(aliases):
                return aliases[index - 1]

        print("[!] Invalid selection.")


def main():
    header()

    secret_files = []

    try:
        # APK
        apk = ask_file(
            "APK file path",
            {".apk"}
        )

        # Keystore
        keystore = ask_file(
            "Keystore file path",
            {".jks", ".keystore", ".p12", ".pfx"}
        )

        # Keystore password
        print("\nPassword characters are hidden.")

        store_password = getpass.getpass(
            "Keystore Password: "
        )

        if not store_password:
            raise RuntimeError("Keystore password cannot be empty.")

        store_file = create_secret_file(store_password)
        secret_files.append(store_file)

        # Find keytool
        keytool = find_keytool()

        # Validate Keystore and discover aliases
        store_type, aliases = inspect_keystore(
            keytool,
            keystore,
            store_file
        )

        # Select Alias
        alias = select_alias(aliases)

        # Key password
        if store_type == "PKCS12":
            key_password = store_password
            print("\n[+] PKCS12: Using the Keystore password for the key.")
        else:
            key_password = getpass.getpass(
                "\nPrivate Key Password (Enter = same password): "
            )

            if not key_password:
                key_password = store_password

        key_file = create_secret_file(key_password)
        secret_files.append(key_file)

        # Output
        default_output = (
            apk.parent / f"{apk.stem}-signed.apk"
        )

        output_input = input(
            f"\nOutput APK [{default_output}]: "
        ).strip().strip('"')

        output = (
            Path(output_input).expanduser()
            if output_input
            else default_output
        ).resolve()

        if output.suffix.lower() != ".apk":
            raise RuntimeError("Output must have .apk extension.")

        if output == apk:
            raise RuntimeError("Cannot overwrite original APK.")

        if output == keystore:
            raise RuntimeError("Output cannot overwrite Keystore.")

        output.parent.mkdir(parents=True, exist_ok=True)

        if output.exists():
            answer = input(
                "\nOutput exists. Overwrite? (y/N): "
            ).strip().lower()

            if answer != "y":
                print("Cancelled.")
                return

        # Android tools
        apksigner, zipalign = find_android_tools()

        print("\n[+] Android tools found:")
        print(f"    apksigner: {apksigner}")
        print(f"    zipalign:  {zipalign}")

        # Temporary workspace on output filesystem
        with tempfile.TemporaryDirectory(
            prefix="apk_signer_",
            dir=output.parent
        ) as temporary_directory:

            temp = Path(temporary_directory)

            aligned_apk = temp / "aligned.apk"
            signed_apk = temp / "signed.apk"

            # Align
            run_command(
                [
                    zipalign,
                    "-p",
                    "-f",
                    "4",
                    apk,
                    aligned_apk
                ],
                "Aligning APK"
            )

            # Sign
            run_command(
                [
                    apksigner,
                    "sign",
                    "--ks",
                    keystore,
                    "--ks-type",
                    store_type,
                    "--ks-key-alias",
                    alias,
                    "--ks-pass",
                    f"file:{store_file}",
                    "--key-pass",
                    f"file:{key_file}",
                    "--out",
                    signed_apk,
                    aligned_apk
                ],
                "Signing APK"
            )

            # Verify
            verification = run_command(
                [
                    apksigner,
                    "verify",
                    "--verbose",
                    "--print-certs",
                    signed_apk
                ],
                "Verifying APK signature"
            )

            if not verification.stdout.strip().startswith("Verifies"):
                raise RuntimeError(
                    "APK signature verification did not succeed."
                )

            # Publish after successful verification
            os.replace(signed_apk, output)

        print("\n" + "=" * 58)
        print("  APK SIGNED AND VERIFIED SUCCESSFULLY")
        print("=" * 58)
        print(f"\nOutput: {output}")
        print(f"Size:   {output.stat().st_size:,} bytes")
        print(f"Alias:  {alias}")
        print(f"Type:   {store_type}")

    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled.")

    except Exception as error:
        print(f"\n[FAILED] {error}")
        sys.exit(1)

    finally:
        for secret in secret_files:
            secret.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
