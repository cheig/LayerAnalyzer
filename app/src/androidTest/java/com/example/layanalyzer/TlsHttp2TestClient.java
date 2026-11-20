package com.example.layanalyzer;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SSLSocket;
import okhttp3.internal.http2.ErrorCode;
import okhttp3.internal.http2.Header;
import okhttp3.internal.http2.Http2Reader;
import okhttp3.internal.http2.Http2Writer;
import okhttp3.internal.http2.Settings;
import okio.BufferedSource;
import okio.ByteString;
import okio.Okio;

final class TlsHttp2TestClient implements Http2Reader.Handler {
    static final class Exchange {
        final byte[] request;
        final byte[] response;
        final byte[] body;

        Exchange(byte[] request, byte[] response, byte[] body) {
            this.request = request;
            this.response = response;
            this.body = body;
        }
    }

    private final Http2Writer writer;
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private boolean finished;
    private boolean headersReceived;
    private String status;

    private TlsHttp2TestClient(Http2Writer writer) {
        this.writer = writer;
    }

    static byte[] decodedBody(byte[] response) throws IOException {
        Http2Writer writer = new Http2Writer(new okio.Buffer(), true);
        Http2Reader reader = new Http2Reader(new okio.Buffer().write(response), true);
        TlsHttp2TestClient handler = new TlsHttp2TestClient(writer);
        reader.readConnectionPreface(handler);
        while (reader.nextFrame(false, handler)) { }
        if (!handler.headersReceived || !handler.finished || !"200".equals(handler.status)) {
            throw new IOException("Decrypted HTTP/2 response must contain status 200 and END_STREAM");
        }
        writer.close();
        reader.close();
        return handler.body.toByteArray();
    }

    static Exchange exchange(SSLSocket socket, String host, String path, String marker) throws IOException {
        ByteArrayOutputStream sent = new ByteArrayOutputStream();
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        InputStream input = new FilterInputStream(socket.getInputStream()) {
            @Override public int read(byte[] buffer, int offset, int length) throws IOException {
                int count = in.read(buffer, offset, length);
                if (count > 0) received.write(buffer, offset, count);
                return count;
            }

            @Override public int read() throws IOException {
                int value = in.read();
                if (value >= 0) received.write(value);
                return value;
            }
        };
        OutputStream output = new FilterOutputStream(socket.getOutputStream()) {
            @Override public void write(byte[] buffer, int offset, int length) throws IOException {
                out.write(buffer, offset, length);
                sent.write(buffer, offset, length);
            }

            @Override public void write(int value) throws IOException {
                out.write(value);
                sent.write(value);
            }
        };
        Http2Writer writer = new Http2Writer(Okio.buffer(Okio.sink(output)), true);
        Http2Reader reader = new Http2Reader(Okio.buffer(Okio.source(input)), true);
        TlsHttp2TestClient handler = new TlsHttp2TestClient(writer);
        writer.connectionPreface();
        writer.settings(new Settings().set(Settings.ENABLE_PUSH, 0));
        writer.headers(true, 1, Arrays.asList(
                new Header(":method", "GET"), new Header(":scheme", "https"),
                new Header(":authority", host), new Header(":path", path),
                new Header("accept-encoding", "identity"), new Header("x-layanalyzer-fixture", marker)));
        writer.flush();
        reader.readConnectionPreface(handler);
        boolean shutdownSent = false;
        int frameCount = 0;
        while (true) {
            try {
                if (!reader.nextFrame(false, handler)) break;
            } catch (SocketTimeoutException timeout) {
                if (!handler.finished || !shutdownSent) throw timeout;
                break;
            }
            if (++frameCount > 256 || received.size() > 262144) throw new IOException("Unbounded HTTP/2 response");
            if (handler.finished && !shutdownSent) {
                writer.goAway(0, ErrorCode.NO_ERROR, new byte[0]);
                shutdownSent = true;
                socket.setSoTimeout(1000);
            }
        }
        if (!handler.headersReceived || !handler.finished || !"200".equals(handler.status)) {
            throw new IOException("HTTP/2 must return status 200 and END_STREAM: status=" + handler.status
                    + " headers=" + handler.headersReceived + " endStream=" + handler.finished);
        }
        writer.close();
        reader.close();
        return new Exchange(sent.toByteArray(), received.toByteArray(), handler.body.toByteArray());
    }

    @Override public void data(boolean endStream, int streamId, BufferedSource source, int length) throws IOException {
        if (streamId != 1 || !headersReceived || finished) throw new IOException("Unexpected HTTP/2 DATA");
        body.write(source.readByteArray(length));
        finished = endStream;
    }

    @Override public void headers(boolean endStream, int streamId, int associatedStreamId, List<Header> headers) {
        if (streamId != 1 || finished) throw new AssertionError("Unexpected HTTP/2 HEADERS");
        headersReceived = true;
        for (Header header : headers) {
            if (header.name.equals(Header.RESPONSE_STATUS)) status = header.value.utf8();
        }
        finished = endStream;
    }

    @Override public void settings(boolean clearPrevious, Settings settings) {
        try {
            writer.applyAndAckSettings(settings);
        } catch (IOException error) {
            throw new AssertionError("HTTP/2 SETTINGS acknowledgement failed", error);
        }
    }

    @Override public void ping(boolean ack, int payload1, int payload2) {
        if (!ack) {
            try {
                writer.ping(true, payload1, payload2);
            } catch (IOException error) {
                throw new AssertionError("HTTP/2 PING acknowledgement failed", error);
            }
        }
    }

    @Override public void rstStream(int streamId, ErrorCode errorCode) {
        throw new AssertionError("HTTP/2 stream reset: " + errorCode);
    }

    @Override public void goAway(int lastGoodStreamId, ErrorCode errorCode, ByteString debugData) {
        if (errorCode != ErrorCode.NO_ERROR || !finished) throw new AssertionError("Premature HTTP/2 GOAWAY");
    }

    @Override public void pushPromise(int streamId, int promisedStreamId, List<Header> headers) throws IOException {
        throw new IOException("HTTP/2 push was disabled");
    }

    @Override public void ackSettings() { }
    @Override public void windowUpdate(int streamId, long increment) { }
    @Override public void priority(int streamId, int dependency, int weight, boolean exclusive) { }
    @Override public void alternateService(int streamId, String origin, ByteString protocol, String host, int port, long maxAge) { }
}
