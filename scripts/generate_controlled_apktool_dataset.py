#!/usr/bin/env python3
"""
Generate controlled, buildable APKs with apktool.

This is the Docker-friendly version of the controlled dataset generator. It
creates minimal smali Android projects, builds them with apktool, and writes
ground_truth_labels.csv. Labels are assigned from template metadata, never from
scanner output.

Expected runtime environment:
  - Python 3
  - apktool on PATH

Example inside apk-scanner container:
  python /tmp/generate_controlled_apktool_dataset.py --output-dir /tmp/controlled_apks --samples-per-category 20 --clean --build
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Snippet:
    variant_id: str
    body: str
    indicators: List[str]
    manifest_attrs: str = ""


@dataclass(frozen=True)
class Template:
    category: str
    template_id: str
    description: str
    smali_factory: Callable[[int], Snippet]
    manifest_attrs: str = ""


def _smali_const_strings(strings: List[str]) -> str:
    lines = []
    for index, value in enumerate(strings):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    const-string v0, "{escaped}"')
        lines.append('    invoke-static {v0}, Lcom/mobilesec/controlled/MainActivity;->sink(Ljava/lang/String;)V')
    return "\n".join(lines)


def _select_variant(index: int, variants: List[Snippet]) -> Snippet:
    return variants[index % len(variants)]


def _weak_hash(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("message_digest_md5", _smali_const_strings(["MessageDigest.getInstance", "MD5"]), ["MessageDigest.getInstance", "MD5"]),
        Snippet("message_digest_sha1", _smali_const_strings(["MessageDigest.getInstance", "SHA-1"]), ["MessageDigest.getInstance", "SHA-1"]),
        Snippet("checksum_md5_password", _smali_const_strings(["md5PasswordHash", "DigestUtils.md5Hex"]), ["DigestUtils.md5Hex", "MD5 password hash"]),
        Snippet("sha1_certificate_pin", _smali_const_strings(["sha1/legacy-certificate-pin", "SHA1PRNG"]), ["SHA-1 pin", "SHA1PRNG"]),
    ])


def _weak_cipher(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("aes_ecb_pkcs5", _smali_const_strings(["Cipher.getInstance", "AES/ECB/PKCS5Padding"]), ["Cipher.getInstance", "AES/ECB/PKCS5Padding"]),
        Snippet("aes_ecb_nopadding", _smali_const_strings(["Cipher.getInstance", "AES/ECB/NoPadding"]), ["Cipher.getInstance", "AES/ECB/NoPadding"]),
        Snippet("des_ecb", _smali_const_strings(["Cipher.getInstance", "DES/ECB/PKCS5Padding"]), ["Cipher.getInstance", "DES/ECB/PKCS5Padding"]),
        Snippet("rc4_stream_cipher", _smali_const_strings(["Cipher.getInstance", "ARC4", "RC4 session token"]), ["Cipher.getInstance", "ARC4/RC4"]),
    ])


def _insecure_random(index: int) -> Snippet:
    variants = [
        Snippet("java_util_random_default", """
    new-instance v0, Ljava/util/Random;
    invoke-direct {v0}, Ljava/util/Random;-><init>()V
""", ["java.util.Random", "Random()"]),
        Snippet("java_util_random_seeded", _smali_const_strings(["new java.util.Random(1337)", "predictable nonce"]), ["java.util.Random(seed)", "predictable nonce"]),
        Snippet("math_random_token", _smali_const_strings(["Math.random", "sessionToken=randomDouble"]), ["Math.random", "session token"]),
        Snippet("sha1prng_seeded", _smali_const_strings(["SecureRandom.getInstance(\"SHA1PRNG\")", "setSeed(123456789)"]), ["SHA1PRNG", "setSeed fixed value"]),
    ]
    return _select_variant(index, variants)


def _weak_rsa(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("rsa_512", _smali_const_strings(["KeyPairGenerator.getInstance", "RSA", "initialize(512)"]), ["RSA", "512-bit key"]),
        Snippet("rsa_768", _smali_const_strings(["KeyPairGenerator.getInstance", "RSA", "initialize(768)"]), ["RSA", "768-bit key"]),
        Snippet("rsa_1024", _smali_const_strings(["KeyPairGenerator.getInstance", "RSA", "initialize(1024)"]), ["RSA", "1024-bit key"]),
        Snippet("rsa_pkcs1_padding", _smali_const_strings(["Cipher.getInstance", "RSA/ECB/PKCS1Padding"]), ["RSA/ECB/PKCS1Padding"]),
    ])


def _api_key(index: int) -> Snippet:
    rng = random.Random(index)
    google_suffix = "".join(rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") for _ in range(35))
    aws_suffix = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(16))
    return _select_variant(index, [
        Snippet("google_api_key", _smali_const_strings([f"AIza{google_suffix}"]), ["AIza Google API key"]),
        Snippet("aws_access_key", _smali_const_strings([f"AKIA{aws_suffix}", "aws_access_key_id"]), ["AKIA AWS access key"]),
        Snippet("stripe_secret_key", _smali_const_strings([f"sk_live_controlled_{index:08d}abcdef"]), ["Stripe sk_live secret key"]),
        Snippet("firebase_key", _smali_const_strings([f"firebase_api_key=AIza{google_suffix}", "google_app_id"]), ["Firebase API key"]),
    ])


def _password(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("literal_password_assignment", _smali_const_strings([f'password="P@ssw0rdControlled{index}!"']), ["hardcoded password assignment"]),
        Snippet("basic_auth_credentials", _smali_const_strings([f"Authorization: Basic admin:Admin{index}!"]), ["basic auth credentials"]),
        Snippet("database_url_password", _smali_const_strings([f"jdbc:mysql://db/mobile?user=root&password=RootPass{index}!"]), ["database URL password"]),
        Snippet("default_admin_credentials", _smali_const_strings([f"default_username=admin", f"default_password=changeMe{index}!"]), ["default admin credentials"]),
    ])


def _secret(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("oauth_token", _smali_const_strings([f"oauth_token=controlledSecretToken{index}ABCDEF1234567890"]), ["OAuth token"]),
        Snippet("jwt_token", _smali_const_strings([f"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb250cm9sbGVkIn0.signature{index}"]), ["JWT-like token"]),
        Snippet("bearer_token", _smali_const_strings([f"Bearer controlledBearerToken{index}abcdef1234567890"]), ["Bearer token"]),
        Snippet("private_key_marker", _smali_const_strings(["-----BEGIN PRIVATE KEY-----", f"controlled-private-key-body-{index}", "-----END PRIVATE KEY-----"]), ["private key material"]),
    ])


def _insecure_http(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("http_login_endpoint", _smali_const_strings([f"http://api{index}.controlled-example.test/login"]), ["HTTP login endpoint"], ' android:usesCleartextTraffic="true"'),
        Snippet("http_api_base_url", _smali_const_strings([f"BASE_URL=http://mobile-api{index}.controlled-example.test/v1/"]), ["HTTP API base URL"], ' android:usesCleartextTraffic="true"'),
        Snippet("webview_mixed_content", _smali_const_strings(["WebSettings.setMixedContentMode", "MIXED_CONTENT_ALWAYS_ALLOW", f"http://cdn{index}.controlled-example.test/script.js"]), ["WebView mixed content", "HTTP script URL"], ' android:usesCleartextTraffic="true"'),
        Snippet("network_security_cleartext", _smali_const_strings(["networkSecurityConfig", "cleartextTrafficPermitted=true"]), ["cleartext traffic permitted"], ' android:usesCleartextTraffic="true"'),
    ])


def _certificate_issue(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("trust_all_cert_manager", _smali_const_strings(["TrustAllCerts", "X509TrustManager", "checkServerTrusted no-op"]), ["TrustAllCerts", "X509TrustManager"]),
        Snippet("allow_all_hostname_verifier", _smali_const_strings(["HostnameVerifier", "return true", "ALLOW_ALL_HOSTNAME_VERIFIER"]), ["HostnameVerifier return true"]),
        Snippet("ssl_context_trust_all", _smali_const_strings(["SSLContext.getInstance(\"TLS\")", "sslContext.init(null, trustAllCerts, null)"]), ["SSLContext trust-all"]),
        Snippet("okhttp_insecure_tls", _smali_const_strings(["OkHttpClient.Builder", "hostnameVerifier((hostname, session) -> true)", "sslSocketFactory(trustAll)"]), ["OkHttp insecure TLS"]),
    ])


def _crypto_medium(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("aes_cbc_nopadding", _smali_const_strings(["Cipher.getInstance", "AES/CBC/NoPadding"]), ["AES/CBC/NoPadding"]),
        Snippet("static_iv_cbc", _smali_const_strings(["IvParameterSpec", "0000000000000000", "AES/CBC/PKCS5Padding"]), ["static IV", "AES/CBC/PKCS5Padding"]),
        Snippet("low_pbkdf2_iterations", _smali_const_strings(["PBKDF2WithHmacSHA1", "iterationCount=1000"]), ["low PBKDF2 iteration count"]),
        Snippet("hardcoded_salt", _smali_const_strings(["PBEKeySpec", "salt=12345678", "iterationCount=1000"]), ["hardcoded salt", "low KDF iterations"]),
    ])


def _crypto_general(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("hardcoded_aes_key", _smali_const_strings(["00112233445566778899aabbccddeeff", "Ljavax/crypto/spec/SecretKeySpec;"]), ["hardcoded AES key", "SecretKeySpec"]),
        Snippet("static_encryption_key", _smali_const_strings([f"ENCRYPTION_KEY=controlledStaticKey{index:04d}", "SecretKeySpec"]), ["static encryption key"]),
        Snippet("hardcoded_hmac_key", _smali_const_strings([f"HMAC_SECRET=controlledHmacKey{index:04d}", "Mac.getInstance(\"HmacSHA256\")"]), ["hardcoded HMAC key"]),
        Snippet("key_in_shared_prefs", _smali_const_strings(["SharedPreferences", "crypto_key", f"stored_key=controlledKey{index:04d}"]), ["crypto key stored in SharedPreferences"]),
    ])


def _secure(index: int) -> Snippet:
    return _select_variant(index, [
        Snippet("secure_hash_random", _smali_const_strings(["SHA-256", "java/security/SecureRandom"]), ["SHA-256", "SecureRandom"]),
        Snippet("secure_tls_marker", _smali_const_strings(["HttpsURLConnection", "platform default TrustManager"]), ["default TLS validation"]),
        Snippet("secure_cipher_marker", _smali_const_strings(["AES/GCM/NoPadding", "random IV"]), ["AES/GCM/NoPadding", "random IV"]),
        Snippet("secure_secret_handling", _smali_const_strings(["AndroidKeyStore", "no hardcoded secrets"]), ["AndroidKeyStore"]),
    ])


TEMPLATES = [
    Template("FIX_WEAK_HASH", "weak_hash", "Intentional weak hash API usage markers.", _weak_hash),
    Template("FIX_WEAK_CIPHER", "weak_cipher", "Intentional weak cipher transformation markers.", _weak_cipher),
    Template("FIX_INSECURE_RANDOM", "insecure_random", "Intentional predictable random generation markers.", _insecure_random),
    Template("FIX_WEAK_RSA_KEY", "weak_rsa", "Intentional weak RSA key or padding markers.", _weak_rsa),
    Template("FIX_EXPOSED_API_KEY", "exposed_api_key", "Intentional hardcoded API key patterns.", _api_key),
    Template("FIX_HARDCODED_PASSWORD", "hardcoded_password", "Intentional hardcoded password patterns.", _password),
    Template("FIX_EXPOSED_SECRET", "exposed_secret", "Intentional hardcoded token/secret patterns.", _secret),
    Template("FIX_INSECURE_HTTP", "insecure_http", "Intentional cleartext HTTP and mixed-content patterns.", _insecure_http),
    Template("FIX_CERTIFICATE_ISSUE", "certificate_issue", "Intentional trust-all TLS and hostname verification markers.", _certificate_issue),
    Template("FIX_CRYPTO_MEDIUM", "crypto_medium", "Intentional medium-severity crypto misuse markers.", _crypto_medium),
    Template("FIX_CRYPTO_GENERAL", "crypto_general", "Intentional hardcoded crypto material markers.", _crypto_general),
    Template("NO_CRITICAL_ISSUES", "secure_control", "Secure control marker only.", _secure),
]


MAIN_ACTIVITY_SMALI = """.class public Lcom/mobilesec/controlled/MainActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {{p0, p1}}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
{body}
    return-void
.end method

.method public static sink(Ljava/lang/String;)V
    .locals 0
    return-void
.end method
"""


APKTOOL_YML = """version: 2.9.3
apkFileName: {apk_name}
isFrameworkApk: false
usesFramework:
  ids:
  - 1
sdkInfo:
  minSdkVersion: '23'
  targetSdkVersion: '35'
packageInfo:
  forcedPackageId: '127'
versionInfo:
  versionCode: '1'
  versionName: '1.0'
resourcesAreCompressed: false
sharedLibrary: false
sparseResources: false
unknownFiles: {{}}
doNotCompress: []
"""


def _manifest(package_name: str, template: Template, snippet: Snippet) -> str:
    manifest_attrs = f"{template.manifest_attrs}{snippet.manifest_attrs}"
    return f"""<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package_name}">
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:theme="@android:style/Theme.Material.Light.NoActionBar" android:label="{template.template_id}"{manifest_attrs}>
        <activity android:name=".MainActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def _styles() -> str:
    return """<resources>
    <style name="AppTheme" parent="@android:style/Theme.Material.Light.NoActionBar" />
</resources>
"""


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    rows = list(rows)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _create_project(project_dir: Path, template: Template, sample_index: int, variant_index: int) -> Snippet:
    package_name = f"com.mobilesec.controlled.{template.template_id}{sample_index:04d}"
    apk_name = f"{template.template_id}_{sample_index:04d}.apk"
    snippet = template.smali_factory(sample_index)
    _write_text(project_dir / "apktool.yml", APKTOOL_YML.format(apk_name=apk_name))
    _write_text(project_dir / "AndroidManifest.xml", _manifest(package_name, template, snippet))
    _write_text(project_dir / "res" / "values" / "styles.xml", _styles())
    _write_text(project_dir / "smali" / "com" / "mobilesec" / "controlled" / "MainActivity.smali", MAIN_ACTIVITY_SMALI.format(body=snippet.body))
    return snippet


def _build_with_apktool(project_dir: Path, apk_path: Path) -> None:
    apktool = shutil.which("apktool")
    if not apktool:
        raise RuntimeError("apktool not found on PATH")
    subprocess.run(
        [apktool, "b", str(project_dir), "-o", str(apk_path), "--use-aapt1", "-a", "/usr/bin/aapt"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def generate(args: argparse.Namespace) -> None:
    output_dir = Path(args.output_dir).resolve()
    projects_dir = output_dir / "projects"
    apks_dir = output_dir / "apks"
    labels_csv = output_dir / "ground_truth_labels.csv"

    if args.clean and output_dir.exists():
        shutil.rmtree(output_dir)
    projects_dir.mkdir(parents=True, exist_ok=True)
    apks_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    rows: List[Dict[str, object]] = []
    failures: List[Dict[str, str]] = []
    sample_id = 0

    for template in TEMPLATES:
        for sample_index in range(args.samples_per_category):
            sample_id += 1
            variant_index = rng.randint(1, 999999)
            project_name = f"{template.template_id}_{sample_index:04d}"
            project_dir = projects_dir / project_name
            apk_path = apks_dir / f"{project_name}.apk"
            if project_dir.exists():
                shutil.rmtree(project_dir)
            snippet = _create_project(project_dir, template, sample_index, variant_index)

            build_status = "not_requested"
            apk_sha256 = ""
            if args.build:
                try:
                    _build_with_apktool(project_dir, apk_path)
                    build_status = "built"
                    apk_sha256 = _sha256(apk_path)
                except subprocess.CalledProcessError as exc:
                    build_status = "failed"
                    failures.append({
                        "project_name": project_name,
                        "category": template.category,
                        "error": (exc.stdout or str(exc))[-4000:],
                    })

            rows.append({
                "sample_id": f"controlled-{sample_id:05d}",
                "project_name": project_name,
                "package_name": f"com.mobilesec.controlled.{template.template_id}{sample_index:04d}",
                "project_path": str(project_dir),
                "apk_path": str(apk_path) if apk_path.exists() else "",
                "apk_sha256": apk_sha256,
                "fix_category": template.category,
                "label_source": "controlled_apktool_template",
                "label_confidence": 1.0,
                "label_review_status": "accepted",
                "template_id": template.template_id,
                "variant_id": snippet.variant_id,
                "ground_truth_rule": template.description,
                "inserted_indicators": json.dumps(snippet.indicators, ensure_ascii=True),
                "inserted_locations": "AndroidManifest.xml; smali/com/mobilesec/controlled/MainActivity.smali",
                "primary_issue_count": 1 if template.category != "NO_CRITICAL_ISSUES" else 0,
                "build_status": build_status,
            })

    _write_csv(labels_csv, rows)
    _write_text(
        output_dir / "controlled_dataset_manifest.json",
        json.dumps({
            "schema_version": 1,
            "generator": Path(__file__).name,
            "label_policy": "Labels are assigned from controlled template metadata, never scanner output.",
            "samples": len(rows),
            "categories": sorted({template.category for template in TEMPLATES}),
            "variant_count": len({row["variant_id"] for row in rows}),
            "build_failures": failures,
        }, indent=2, ensure_ascii=True),
    )

    print(f"Generated labels: {labels_csv}")
    print(f"Generated projects: {projects_dir}")
    if args.build:
        built = sum(1 for row in rows if row["build_status"] == "built")
        print(f"Built APKs: {built}/{len(rows)}")
        print(f"APK directory: {apks_dir}")
        if failures:
            print(f"Build failures: {len(failures)}")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate controlled APKs with trusted fix_category labels.")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--samples-per-category", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--clean", action="store_true")
    parser.add_argument("--build", action="store_true")
    args = parser.parse_args(argv)
    if args.samples_per_category < 1:
        raise ValueError("--samples-per-category must be >= 1")
    return args


def main(argv: List[str]) -> int:
    try:
        generate(parse_args(argv))
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
