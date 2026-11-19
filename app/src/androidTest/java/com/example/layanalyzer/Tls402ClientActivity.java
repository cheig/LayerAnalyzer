// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer;

import android.app.Activity;
import android.content.Intent;
import android.net.http.SslError;
import android.os.Bundle;
import android.webkit.SslErrorHandler;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.HttpsURLConnection;
import java.net.URL;
import org.json.JSONObject;

/** A client in the test APK's own process/UID and network security config.
 * Reports only a body digest or error category. Never ignores SSL errors.
 */
public class Tls402ClientActivity extends Activity {
    private final AtomicBoolean reported = new AtomicBoolean();
    private WebView webView;
    private Intent resultIntent;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        String url = getIntent().getStringExtra("url");
        if (url == null || !url.matches("https://localhost:[0-9]{1,5}/")) {
            report(false, "INVALID_TEST_URL", "");
            return;
        }
        if ("webview".equals(getIntent().getStringExtra("mode"))) {
            webView = new WebView(this);
            setContentView(webView);
            webView.getSettings().setJavaScriptEnabled(true);
            webView.setWebViewClient(new WebViewClient() {
                @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                    handler.cancel();
                    report(false, "WEBVIEW_SSL_" + error.getPrimaryError(), "");
                }
                @Override public void onPageFinished(WebView view, String loaded) {
                    if (reported.get()) return;
                    view.evaluateJavascript("document.body.innerText", value -> {
                        try {
                            String text = new org.json.JSONArray("[" + value + "]").getString(0);
                            report(true, "", sha256(text.getBytes(StandardCharsets.UTF_8)));
                        } catch (Exception error) { report(false, "WEBVIEW_BODY", ""); }
                    });
                }
            });
            webView.loadUrl(url);
        } else {
            new Thread(() -> {
                HttpsURLConnection connection = null;
                try {
                    connection = (HttpsURLConnection) new URL(url).openConnection();
                    connection.setConnectTimeout(10000);
                    connection.setReadTimeout(10000);
                    connection.setInstanceFollowRedirects(false);
                    ByteArrayOutputStream body = new ByteArrayOutputStream();
                    byte[] buffer = new byte[1024];
                    try (java.io.InputStream input = connection.getInputStream()) {
                        int count;
                        while ((count = input.read(buffer)) != -1) {
                            if (body.size() + count > 4096) throw new java.io.IOException("body budget");
                            body.write(buffer, 0, count);
                        }
                    }
                    if (connection.getResponseCode() != 200) throw new java.io.IOException("status");
                    report(true, "", sha256(body.toByteArray()));
                } catch (Exception error) { report(false, error.getClass().getSimpleName(), ""); }
                finally { if (connection != null) connection.disconnect(); }
            }, "tls402-independent-client").start();
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte value : MessageDigest.getInstance("SHA-256").digest(bytes)) result.append(String.format("%02x", value));
        return result.toString();
    }

    private void report(boolean ok, String error, String bodySha256) {
        if (!reported.compareAndSet(false, true)) return;
        try {
            JSONObject value = new JSONObject().put("ok", ok).put("error", error).put("bodySha256", bodySha256)
                .put("package", getPackageName()).put("targetSdk", getApplicationInfo().targetSdkVersion)
                .put("debuggable", (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0);
            resultIntent = new Intent("com.layeranalyzer.TLS402_CLIENT_RESULT").setPackage("com.layeranalyzer.android.debug")
                .putExtra("requestId", getIntent().getStringExtra("requestId")).putExtra("result", value.toString());
        } catch (Exception errorIgnored) { /* Caller treats a missing result as failure. */ }
        runOnUiThread(this::finish);
    }

    @Override public void onDestroy() {
        if (webView != null) { webView.stopLoading(); webView.destroy(); }
        super.onDestroy();
        // Signal only after this Activity is gone. Otherwise the next shell
        // launch can race finish(), and MIUI can discard the second request.
        if (resultIntent != null) sendBroadcast(resultIntent);
    }
}
