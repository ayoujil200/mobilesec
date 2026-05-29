#!/usr/bin/env python3
"""
Generate a controlled Android security-label dataset.

This script creates small Android projects where each project contains exactly
one intentional primary weakness. The ground-truth label comes from template
metadata, not from scanner output. Scanner output should only be used later to
calculate model input features.

Default output:
  backend/ml-model/experiments/controlled_android_dataset/

Examples:
  python scripts/generate_controlled_android_dataset.py --samples-per-category 10
  python scripts/generate_controlled_android_dataset.py --samples-per-category 5 --build

The optional --build step requires a local Gradle + Android SDK installation.
It uses subprocess without shell=True and only runs inside generated projects.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "backend" / "ml-model" / "experiments" / "controlled_android_dataset"

ANDROID_GRADLE_PLUGIN_VERSION = "8.2.2"
ANDROID_COMPILE_SDK = 35
ANDROID_MIN_SDK = 23


@dataclass(frozen=True)
class Template:
    category: str
    template_id: str
    description: str
    java_body_factory: Callable[[int], str]
    manifest_attrs: str = ""
    network_security_config: Optional[str] = None


def _java_string(value: str) -> str:
    return json.dumps(value)


def _random_suffix(rng: random.Random, length: int = 8) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _weak_hash_body(index: int) -> str:
    algorithm = "MD5" if index % 2 == 0 else "SHA-1"
    return f"""
        try {{
            MessageDigest digest = MessageDigest.getInstance({_java_string(algorithm)});
            byte[] value = digest.digest("controlled-input-{index}".getBytes(StandardCharsets.UTF_8));
            Log.d("ControlledDataset", "weak hash bytes=" + value.length);
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "hash error", exception);
        }}
"""


def _weak_cipher_body(index: int) -> str:
    transformation = "AES/ECB/PKCS5Padding" if index % 2 == 0 else "DES/ECB/PKCS5Padding"
    key_algorithm = "AES" if transformation.startswith("AES") else "DES"
    key_bytes = "0123456789abcdef" if key_algorithm == "AES" else "12345678"
    return f"""
        try {{
            Cipher cipher = Cipher.getInstance({_java_string(transformation)});
            SecretKeySpec key = new SecretKeySpec({_java_string(key_bytes)}.getBytes(StandardCharsets.UTF_8), {_java_string(key_algorithm)});
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] value = cipher.doFinal("controlled-plaintext-{index}".getBytes(StandardCharsets.UTF_8));
            Log.d("ControlledDataset", "weak cipher bytes=" + value.length);
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "cipher error", exception);
        }}
"""


def _insecure_random_body(index: int) -> str:
    return f"""
        Random random = new Random({index + 1000});
        byte[] cryptoNonce = new byte[16];
        random.nextBytes(cryptoNonce);
        Log.d("ControlledDataset", "weak random nonce=" + Arrays.toString(cryptoNonce));
"""


def _weak_rsa_body(index: int) -> str:
    return f"""
        try {{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Log.d("ControlledDataset", "weak rsa public=" + keyPair.getPublic().getAlgorithm());
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "rsa error", exception);
        }}
"""


def _api_key_body(index: int) -> str:
    suffix = _random_suffix(random.Random(index), 35)
    return f"""
        String googleApiKey = "AIza{suffix}";
        Log.d("ControlledDataset", "api key length=" + googleApiKey.length());
"""


def _password_body(index: int) -> str:
    return f"""
        String password = "P@ssw0rdControlled{index}!";
        Log.d("ControlledDataset", "password length=" + password.length());
"""


def _secret_body(index: int) -> str:
    return f"""
        String oauth_token = "oauth_token=controlledSecretToken{index}ABCDEF1234567890";
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjb250cm9sbGVkIn0.signature{index}";
        Log.d("ControlledDataset", "secret lengths=" + oauth_token.length() + jwt.length());
"""


def _insecure_http_body(index: int) -> str:
    return f"""
        String endpoint = "http://api{index}.controlled-example.test/login";
        Log.d("ControlledDataset", "cleartext endpoint=" + endpoint);
"""


def _certificate_issue_body(index: int) -> str:
    return f"""
        try {{
            TrustManager[] trustAllCerts = new TrustManager[] {{
                new X509TrustManager() {{
                    public X509Certificate[] getAcceptedIssuers() {{ return new X509Certificate[0]; }}
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {{ }}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {{ }}
                }}
            }};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
            Log.d("ControlledDataset", "trust-all tls configured {index}");
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "tls error", exception);
        }}
"""


def _crypto_medium_body(index: int) -> str:
    return f"""
        try {{
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes(StandardCharsets.UTF_8), "AES");
            IvParameterSpec iv = new IvParameterSpec("0000000000000000".getBytes(StandardCharsets.UTF_8));
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] value = cipher.doFinal("controlledblock16".getBytes(StandardCharsets.UTF_8));
            Log.d("ControlledDataset", "medium crypto bytes=" + value.length);
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "medium crypto error", exception);
        }}
"""


def _crypto_general_body(index: int) -> str:
    return f"""
        try {{
            String hardcodedKey = "00112233445566778899aabbccddeeff";
            SecretKeySpec key = new SecretKeySpec(hardcodedKey.getBytes(StandardCharsets.UTF_8), "AES");
            Log.d("ControlledDataset", "hardcoded crypto key=" + key.getAlgorithm() + "{index}");
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "general crypto error", exception);
        }}
"""


def _secure_body(index: int) -> str:
    return f"""
        try {{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            SecureRandom secureRandom = new SecureRandom();
            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            byte[] value = digest.digest(("controlled-secure-{index}" + Arrays.toString(salt)).getBytes(StandardCharsets.UTF_8));
            Log.d("ControlledDataset", "secure bytes=" + value.length);
        }} catch (Exception exception) {{
            Log.e("ControlledDataset", "secure error", exception);
        }}
"""


TEMPLATES: List[Template] = [
    Template("FIX_WEAK_HASH", "weak_hash", "Intentional MD5/SHA-1 hash use.", _weak_hash_body),
    Template("FIX_WEAK_CIPHER", "weak_cipher", "Intentional AES/ECB or DES cipher use.", _weak_cipher_body),
    Template("FIX_INSECURE_RANDOM", "insecure_random", "Intentional java.util.Random use for crypto nonce.", _insecure_random_body),
    Template("FIX_WEAK_RSA_KEY", "weak_rsa", "Intentional 1024-bit RSA key generation.", _weak_rsa_body),
    Template("FIX_EXPOSED_API_KEY", "exposed_api_key", "Intentional hardcoded API key.", _api_key_body),
    Template("FIX_HARDCODED_PASSWORD", "hardcoded_password", "Intentional hardcoded password.", _password_body),
    Template("FIX_EXPOSED_SECRET", "exposed_secret", "Intentional hardcoded token/secret.", _secret_body),
    Template(
        "FIX_INSECURE_HTTP",
        "insecure_http",
        "Intentional cleartext HTTP endpoint.",
        _insecure_http_body,
        manifest_attrs=' android:usesCleartextTraffic="true"',
    ),
    Template("FIX_CERTIFICATE_ISSUE", "certificate_issue", "Intentional trust-all TLS validation bypass.", _certificate_issue_body),
    Template("FIX_CRYPTO_MEDIUM", "crypto_medium", "Intentional AES/CBC/NoPadding use.", _crypto_medium_body),
    Template("FIX_CRYPTO_GENERAL", "crypto_general", "Intentional hardcoded cryptographic key.", _crypto_general_body),
    Template("NO_CRITICAL_ISSUES", "secure_control", "Secure control app with no intentional issue.", _secure_body),
]


JAVA_IMPORTS = """package {package_name};

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class MainActivity extends Activity {{
    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        runControlledCase();
    }}

    private void runControlledCase() {{
{body}
    }}
}}
"""


def _ensure_under_repo(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise ValueError(f"Refusing to write outside repository: {resolved}") from exc
    return resolved


def _safe_rmtree(path: Path) -> None:
    resolved = _ensure_under_repo(path)
    if resolved.exists():
        shutil.rmtree(resolved)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _project_name(template: Template, index: int) -> str:
    return f"{template.template_id}_{index:04d}"


def _package_name(template: Template, index: int) -> str:
    return f"com.mobilesec.controlled.{template.template_id}{index:04d}"


def _settings_gradle(project_name: str) -> str:
    return f"""pluginManagement {{
    repositories {{
        google()
        mavenCentral()
        gradlePluginPortal()
    }}
}}
dependencyResolutionManagement {{
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {{
        google()
        mavenCentral()
    }}
}}
rootProject.name = "{project_name}"
include ":app"
"""


def _root_build_gradle() -> str:
    return f"""plugins {{
    id "com.android.application" version "{ANDROID_GRADLE_PLUGIN_VERSION}" apply false
}}
"""


def _app_build_gradle(package_name: str) -> str:
    return f"""plugins {{
    id "com.android.application"
}}

android {{
    namespace "{package_name}"
    compileSdk {ANDROID_COMPILE_SDK}

    defaultConfig {{
        applicationId "{package_name}"
        minSdk {ANDROID_MIN_SDK}
        targetSdk {ANDROID_COMPILE_SDK}
        versionCode 1
        versionName "1.0"
    }}

    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }}
}}
"""


def _manifest(package_name: str, template: Template) -> str:
    return f"""<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:theme="@style/AppTheme"
        android:label="{template.template_id}"{template.manifest_attrs}>
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


def _styles_xml() -> str:
    return """<resources>
    <style name="AppTheme" parent="android:style/Theme.Material.Light.NoActionBar" />
</resources>
"""


def _create_project(project_dir: Path, template: Template, sample_index: int, variant_index: int) -> Dict[str, str]:
    project_name = _project_name(template, sample_index)
    package_name = _package_name(template, sample_index)
    java_package_dir = project_dir / "app" / "src" / "main" / "java" / Path(*package_name.split("."))

    _write_text(project_dir / "settings.gradle", _settings_gradle(project_name))
    _write_text(project_dir / "build.gradle", _root_build_gradle())
    _write_text(project_dir / "app" / "build.gradle", _app_build_gradle(package_name))
    _write_text(project_dir / "app" / "src" / "main" / "AndroidManifest.xml", _manifest(package_name, template))
    _write_text(project_dir / "app" / "src" / "main" / "res" / "values" / "styles.xml", _styles_xml())
    _write_text(
        java_package_dir / "MainActivity.java",
        JAVA_IMPORTS.format(package_name=package_name, body=template.java_body_factory(variant_index)),
    )

    return {
        "project_name": project_name,
        "package_name": package_name,
        "project_path": str(project_dir.relative_to(REPO_ROOT)),
    }


def _find_gradle() -> Optional[str]:
    for candidate in ["gradle", "gradle.bat"]:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _build_project(project_dir: Path, gradle_executable: str) -> Optional[Path]:
    subprocess.run(
        [gradle_executable, "--no-daemon", ":app:assembleDebug"],
        cwd=str(project_dir),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    apk = project_dir / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
    return apk if apk.exists() else None


def _write_csv(path: Path, rows: Iterable[Dict[str, object]]) -> None:
    rows = list(rows)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def generate_dataset(args: argparse.Namespace) -> None:
    output_dir = _ensure_under_repo(Path(args.output_dir))
    projects_dir = output_dir / "projects"
    apks_dir = output_dir / "apks"
    labels_csv = output_dir / "ground_truth_labels.csv"
    manifest_json = output_dir / "controlled_dataset_manifest.json"

    if args.clean:
        _safe_rmtree(output_dir)

    projects_dir.mkdir(parents=True, exist_ok=True)
    apks_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(args.seed)
    templates = list(TEMPLATES)
    if args.categories:
        requested = set(args.categories)
        templates = [template for template in templates if template.category in requested]
        missing = requested - {template.category for template in templates}
        if missing:
            raise ValueError(f"Unknown categories: {sorted(missing)}")

    gradle = _find_gradle() if args.build else None
    if args.build and not gradle:
        raise RuntimeError("Gradle not found on PATH. Install Gradle or run without --build.")

    rows: List[Dict[str, object]] = []
    build_failures: List[Dict[str, str]] = []

    sample_number = 0
    for template in templates:
        for sample_index in range(args.samples_per_category):
            sample_number += 1
            variant_index = rng.randint(1, 999999)
            project_name = _project_name(template, sample_index)
            project_dir = projects_dir / project_name
            if project_dir.exists():
                _safe_rmtree(project_dir)
            project_dir.mkdir(parents=True)

            project_info = _create_project(project_dir, template, sample_index, variant_index)
            apk_path = ""
            apk_sha256 = ""
            build_status = "not_requested"

            if args.build and gradle:
                try:
                    built_apk = _build_project(project_dir, gradle)
                    if built_apk:
                        target_apk = apks_dir / f"{project_name}.apk"
                        shutil.copyfile(built_apk, target_apk)
                        apk_path = str(target_apk.relative_to(REPO_ROOT))
                        apk_sha256 = _sha256(target_apk)
                        build_status = "built"
                    else:
                        build_status = "missing_apk"
                except subprocess.CalledProcessError as exc:
                    build_status = "failed"
                    build_failures.append({
                        "project": project_name,
                        "category": template.category,
                        "error": (exc.stdout or str(exc))[-4000:],
                    })

            rows.append({
                "sample_id": f"controlled-{sample_number:05d}",
                "project_name": project_info["project_name"],
                "package_name": project_info["package_name"],
                "project_path": project_info["project_path"],
                "apk_path": apk_path,
                "apk_sha256": apk_sha256,
                "fix_category": template.category,
                "label_source": "controlled_template",
                "label_confidence": 1.0,
                "label_review_status": "accepted",
                "template_id": template.template_id,
                "ground_truth_rule": template.description,
                "primary_issue_count": 1 if template.category != "NO_CRITICAL_ISSUES" else 0,
                "build_status": build_status,
            })

    _write_csv(labels_csv, rows)
    _write_text(
        manifest_json,
        json.dumps({
            "schema_version": 1,
            "generated_by": Path(__file__).name,
            "seed": args.seed,
            "samples_per_category": args.samples_per_category,
            "categories": [template.category for template in templates],
            "label_policy": "Labels are assigned from controlled template metadata, never from scanner output.",
            "paths": {
                "labels_csv": str(labels_csv.relative_to(REPO_ROOT)),
                "projects_dir": str(projects_dir.relative_to(REPO_ROOT)),
                "apks_dir": str(apks_dir.relative_to(REPO_ROOT)),
            },
            "build_requested": bool(args.build),
            "build_failures": build_failures,
        }, indent=2, ensure_ascii=True),
    )

    print(f"Generated {len(rows)} controlled samples")
    print(f"Labels: {labels_csv}")
    print(f"Projects: {projects_dir}")
    if args.build:
        built_count = sum(1 for row in rows if row["build_status"] == "built")
        print(f"Built APKs: {built_count}/{len(rows)}")
        if build_failures:
            print(f"Build failures: {len(build_failures)}. See {manifest_json}")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate controlled Android projects with trusted fix_category labels.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory under this repository.")
    parser.add_argument("--samples-per-category", type=int, default=5, help="Number of generated projects per category.")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed.")
    parser.add_argument("--clean", action="store_true", help="Delete the output directory before generation.")
    parser.add_argument("--build", action="store_true", help="Build debug APKs with local Gradle/Android SDK.")
    parser.add_argument(
        "--categories",
        nargs="*",
        help="Optional category subset. Defaults to all supported fix categories.",
    )
    args = parser.parse_args(argv)

    if args.samples_per_category < 1:
        raise ValueError("--samples-per-category must be >= 1")

    return args


def main(argv: List[str]) -> int:
    try:
        args = parse_args(argv)
        generate_dataset(args)
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
