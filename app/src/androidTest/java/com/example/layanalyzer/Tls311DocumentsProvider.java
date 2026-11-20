// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer;

import android.database.Cursor;
import android.database.MatrixCursor;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract.Document;
import android.provider.DocumentsContract.Root;
import android.provider.DocumentsProvider;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Remote test-APK provider: platform Java only; the target APK owns the Kotlin runtime. */
public class Tls311DocumentsProvider extends DocumentsProvider {
    private volatile int opened;
    private volatile int deleted;
    private CountDownLatch gate = new CountDownLatch(0);
    private File files() {
        File root = new File(getContext().getFilesDir(), "tls311-documents");
        root.mkdirs();
        return root;
    }
    private File file(String id) {
        if (!id.matches("[A-Za-z0-9._-]+") || id.equals(".") || id.equals(".."))
            throw new IllegalArgumentException("Fixture id");
        return new File(files(), id);
    }
    @Override public boolean onCreate() { return true; }
    @Override public Cursor queryRoots(String[] projection) {
        MatrixCursor result = new MatrixCursor(projection != null ? projection : new String[]{
                Root.COLUMN_ROOT_ID, Root.COLUMN_DOCUMENT_ID, Root.COLUMN_TITLE, Root.COLUMN_FLAGS,
                Root.COLUMN_MIME_TYPES, Root.COLUMN_AVAILABLE_BYTES});
        result.newRow().add(Root.COLUMN_ROOT_ID, "root").add(Root.COLUMN_DOCUMENT_ID, "root")
                .add(Root.COLUMN_TITLE, "TLS-311 fixtures")
                .add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_CREATE | Root.FLAG_LOCAL_ONLY)
                .add(Root.COLUMN_MIME_TYPES, "*/*").add(Root.COLUMN_AVAILABLE_BYTES, 100000000L);
        return result;
    }
    private MatrixCursor cursor(String[] projection) {
        return new MatrixCursor(projection != null ? projection : new String[]{
                Document.COLUMN_DOCUMENT_ID, Document.COLUMN_DISPLAY_NAME, Document.COLUMN_MIME_TYPE,
                Document.COLUMN_FLAGS, Document.COLUMN_SIZE});
    }
    private void row(MatrixCursor cursor, String id) {
        cursor.newRow().add(Document.COLUMN_DOCUMENT_ID, id).add(Document.COLUMN_DISPLAY_NAME, id)
                .add(Document.COLUMN_MIME_TYPE, id.equals("root") ? Document.MIME_TYPE_DIR : "application/zip")
                .add(Document.COLUMN_FLAGS, id.equals("root") ? Document.FLAG_DIR_SUPPORTS_CREATE
                        : Document.FLAG_SUPPORTS_WRITE | Document.FLAG_SUPPORTS_DELETE)
                .add(Document.COLUMN_SIZE, id.equals("root") ? 0L : file(id).length());
    }
    @Override public Cursor queryDocument(String id, String[] projection) throws FileNotFoundException {
        if (!id.equals("root") && !file(id).exists()) throw new FileNotFoundException();
        MatrixCursor result = cursor(projection);
        row(result, id);
        return result;
    }
    @Override public Cursor queryChildDocuments(String parent, String[] projection, String order) {
        MatrixCursor result = cursor(projection);
        File[] children = files().listFiles();
        if (children != null) for (File child : children) row(result, child.getName());
        return result;
    }
    @Override public String createDocument(String parent, String mime, String name) throws FileNotFoundException {
        if (!parent.equals("root")) throw new IllegalArgumentException();
        try (FileOutputStream output = new FileOutputStream(file(name))) { output.flush(); }
        catch (IOException error) { throw new FileNotFoundException("Fixture creation"); }
        return name;
    }
    @Override public ParcelFileDescriptor openDocument(String id, String mode, CancellationSignal signal)
            throws FileNotFoundException {
        if (mode.contains("w")) {
            opened++;
            if (id.startsWith("blocked")) try {
                if (!gate.await(30, TimeUnit.SECONDS)) throw new FileNotFoundException("Fixture gate timeout");
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new FileNotFoundException("Interrupted");
            }
            if (id.startsWith("fail") && opened == 1) {
                try (FileOutputStream output = new FileOutputStream(file(id))) {
                    output.write(new byte[]{1, 2, 3});
                } catch (IOException error) { throw new FileNotFoundException("Fixture prefix"); }
                throw new FileNotFoundException("Synthetic write failure");
            }
            if (id.equals("fail-all")) throw new FileNotFoundException("Synthetic truncate refusal");
        }
        return ParcelFileDescriptor.open(file(id), ParcelFileDescriptor.parseMode(mode));
    }
    @Override public void deleteDocument(String id) throws FileNotFoundException {
        deleted++;
        if (id.equals("fail-truncate") || id.equals("fail-all"))
            throw new FileNotFoundException("Synthetic delete refusal");
        if (!file(id).delete()) throw new FileNotFoundException();
    }
    @Override public Bundle call(String method, String arg, Bundle extras) {
        Bundle result = new Bundle();
        switch (method) {
            case "tls311-reset":
                gate.countDown();
                File[] children = files().listFiles();
                if (children != null) for (File child : children)
                    if (!child.delete()) throw new IllegalStateException("Fixture cleanup");
                opened = 0; deleted = 0; gate = new CountDownLatch(1);
                return result;
            case "tls311-release": gate.countDown(); return result;
            case "tls311-state":
                result.putInt("opened", opened); result.putInt("deleted", deleted); return result;
            default: return super.call(method, arg, extras);
        }
    }
}
