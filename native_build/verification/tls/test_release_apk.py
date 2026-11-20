"""Failure-path regressions for the final-APK gate, not Android runtime tests."""
import copy
import struct
import unittest

from check_release_apk import (CALLBACK, CALLBACK_METHODS, EXCEPTION, NATIVE, PROGRESS_CALLBACK_METHODS, TLS_METHODS,
                               check_dex, dependency_closure, jni_name, scan_entry)
from dex_contract import read_dex


def cls(methods=None, access=1, parent=None, interfaces=()):
    return {"access": access, "super": parent, "interfaces": list(interfaces), "methods": methods or {}}


def fixture():
    native = {(name, "()V"): {"access": 0x101, "code": 0} for name in TLS_METHODS}
    classes = {NATIVE: cls(native), CALLBACK: cls(access=0x601),
               EXCEPTION: cls({("<init>", "(Ljava/lang/String;)V"): {"access": 1, "code": 1}}),
               "Limpl;": cls({method: {"access": 1, "code": 1} for method in CALLBACK_METHODS}, interfaces=[CALLBACK])}
    for interface, method in PROGRESS_CALLBACK_METHODS.items():
        classes[interface] = cls({method: {"access": 0x401, "code": 0}}, access=0x601)
        classes[interface[:-1] + "Impl;"] = cls({method: {"access": 1, "code": 1}}, interfaces=[interface])
    return classes, [jni_name(NATIVE, name) for name in TLS_METHODS]


class ReleaseApkTest(unittest.TestCase):
    def test_preserved_contract(self):
        classes, exports = fixture()
        self.assertEqual(["Limpl;"], check_dex(classes, exports, True)["callbackImplementations"])

    def test_native_name_without_definition_is_rejected(self):
        classes, exports = fixture()
        del classes[NATIVE]["methods"][("startTlsProxy", "()V")]
        with self.assertRaisesRegex(ValueError, "declarations"):
            check_dex(classes, exports, True)

    def test_progress_interface_method_must_survive_r8(self):
        for interface in PROGRESS_CALLBACK_METHODS:
            classes, exports = fixture()
            classes[interface]["methods"].clear()
            with self.assertRaisesRegex(ValueError, "progress callback interface"):
                check_dex(classes, exports, True)

    def test_progress_implementations_must_survive_r8(self):
        for interface, method in PROGRESS_CALLBACK_METHODS.items():
            for access in (0, 2, 9, 0x401):
                classes, exports = fixture()
                classes[interface[:-1] + "Impl;"]["methods"][method] = {"access": access, "code": 1}
                with self.assertRaisesRegex(ValueError, "progress callback missing"):
                    check_dex(classes, exports, True)
            classes, exports = fixture()
            classes[interface[:-1] + "Impl;"]["methods"].clear()
            with self.assertRaisesRegex(ValueError, "progress callback missing"):
                check_dex(classes, exports, True)

    def test_progress_callback_requires_a_concrete_implementation(self):
        classes, exports = fixture()
        del classes[next(iter(PROGRESS_CALLBACK_METHODS))[:-1] + "Impl;"]
        with self.assertRaisesRegex(ValueError, "no concrete JNI progress"):
            check_dex(classes, exports, True)

    def test_stripped_jni_export_or_duplicate_is_rejected(self):
        for duplicate in (False, True):
            classes, exports = fixture()
            exports = exports + exports[:1] if duplicate else exports[1:]
            with self.assertRaisesRegex(ValueError, "unique"):
                check_dex(classes, exports, True)

    def test_callback_descriptor_or_access_change_is_rejected(self):
        for mutation in ("descriptor", "static", "private", "abstract"):
            classes, exports = fixture()
            method = ("prepareSocket", "(IJ)Ljava/lang/String;")
            if mutation == "descriptor":
                classes["Limpl;"]["methods"][("prepareSocket", "(II)Ljava/lang/String;")] = classes["Limpl;"]["methods"].pop(method)
            else:
                classes["Limpl;"]["methods"][method]["access"] = {"static": 9, "private": 2, "abstract": 0x401}[mutation]
            with self.assertRaisesRegex(ValueError, "callback"):
                check_dex(classes, exports, True)

    def test_inherited_concrete_callback_is_resolved(self):
        classes, exports = fixture()
        classes["Lbase;"] = classes.pop("Limpl;")
        classes["Lbase;"]["access"] = 0x401
        classes["Limpl;"] = cls(parent="Lbase;")
        self.assertEqual(["Limpl;"], check_dex(classes, exports, True)["callbackImplementations"])

    def test_exception_name_and_string_constructor_are_required(self):
        for renamed in (True, False):
            classes, exports = fixture()
            if renamed:
                classes["La;"] = classes.pop(EXCEPTION)
            else:
                classes[EXCEPTION]["methods"].clear()
            with self.assertRaisesRegex(ValueError, "ThrowNew"):
                check_dex(classes, exports, True)

    def test_release_rejects_dormant_probe_declaration(self):
        classes, exports = fixture()
        classes[NATIVE]["methods"][("runTlsSocketProbe", "()V")] = {"access": 0x101, "code": 0}
        with self.assertRaisesRegex(ValueError, "debug/probe"):
            check_dex(classes, exports, True)

    def test_release_rejects_probe_interface(self):
        classes, exports = fixture()
        classes["Lcom/example/layanalyzer/NativeEngine$TlsSocketProbeCallback;"] = cls(access=0x601)
        with self.assertRaisesRegex(ValueError, "P0 probe class"):
            check_dex(classes, exports, True)

    def test_dependency_closure_allows_only_packaged_or_public(self):
        libs = {"a.so": {"soname": "a.so", "needed": ["b.so", "libc.so"]}, "b.so": {"soname": "b.so", "needed": []}}
        dependency_closure(libs)
        for bad in ("libssl.so", "libmissing.so"):
            broken = copy.deepcopy(libs)
            broken["a.so"]["needed"].append(bad)
            with self.assertRaisesRegex(ValueError, "dependency"):
                dependency_closure(broken)

    def test_soname_and_eager_go_linkage_are_rejected(self):
        for lib in ({"soname": "wrong.so", "needed": []}, {"soname": "a.so", "needed": ["liblayanalyzer_tls.so"]}):
            with self.assertRaises(ValueError):
                dependency_closure({"a.so": lib, "liblayanalyzer_tls.so": {"soname": "liblayanalyzer_tls.so", "needed": ["libc.so"]}})

    def test_probe_test_roots_and_secret_assets_are_rejected(self):
        for name, payload in (("lib/arm64-v8a/a.so", b"la_tls_probe_start"), ("assets/ca.der", b"known-root"),
                              ("assets/a.pem", b"-----BEGIN PRIVATE KEY-----"), ("assets/tls/fixtures/a", b""),
                              ("assets/a.keys", b""), ("assets/a", b"CLIENT_RANDOM " + b"A" * 64 + b" " + b"B" * 96)):
            with self.assertRaises(ValueError):
                scan_entry(name, payload, {b"known-root"}, True)

    def test_legitimate_public_key_and_tls_encoder_are_not_secrets(self):
        scan_entry("assets/scenario_package_public_key.pem", b"-----BEGIN PUBLIC KEY-----", set(), True)
        scan_entry("lib/arm64-v8a/liblayanalyzer_tls.so", b"-----BEGIN PRIVATE KEY-----", set(), True)

    def test_debug_entry_rejected_only_in_release(self):
        scan_entry("classes.dex", b"perf_export", set(), False)
        with self.assertRaisesRegex(ValueError, "debug entry"):
            scan_entry("classes.dex", b"perf_export", set(), True)

    def test_dex_method_reference_is_not_a_definition(self):
        # Minimal DEX with one class, a defined method and an unused method_id.
        data = bytearray(112)
        data[:8] = b"dex\n035\0"
        string_ids = len(data)
        data.extend(b"\0" * 16)
        type_ids = len(data)
        data.extend(struct.pack("<II", 0, 1))
        protos = len(data)
        data.extend(struct.pack("<III", 1, 1, 0))
        method_ids = len(data)
        data.extend(struct.pack("<HHIHHI", 0, 0, 2, 0, 0, 3))
        class_defs = len(data)
        data.extend(b"\0" * 32)
        class_data = len(data)
        data.extend(bytes([0, 0, 1, 0, 0, 1, 0]))
        for index, value in enumerate((b"Ltest;", b"V", b"defined", b"reference")):
            struct.pack_into("<I", data, string_ids + index * 4, len(data))
            data.extend(bytes([len(value)]) + value + b"\0")
        for offset, count, start in ((56, 4, string_ids), (64, 2, type_ids), (72, 1, protos), (88, 2, method_ids), (96, 1, class_defs)):
            struct.pack_into("<II", data, offset, count, start)
        struct.pack_into("<8I", data, class_defs, 0, 1, 0xffffffff, 0, 0, 0, class_data, 0)
        self.assertEqual({("defined", "()V")}, set(read_dex(data)["Ltest;"]["methods"]))


if __name__ == "__main__":
    unittest.main()
