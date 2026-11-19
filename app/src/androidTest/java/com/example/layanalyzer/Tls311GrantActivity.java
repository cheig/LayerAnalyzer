// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

/** Grants only the test provider's fixtures, from its owning test-APK UID. */
public class Tls311GrantActivity extends Activity {
    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        grantUriPermission("com.layeranalyzer.android.debug",
                Uri.parse("content://com.layeranalyzer.tls311.test.documents"),
                Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        | Intent.FLAG_GRANT_PREFIX_URI_PERMISSION);
        finish();
    }
}
