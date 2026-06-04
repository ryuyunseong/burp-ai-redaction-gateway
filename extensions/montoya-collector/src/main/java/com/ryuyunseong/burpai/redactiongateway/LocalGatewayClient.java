package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

final class LocalGatewayClient {
    private static final URI DEFAULT_ENDPOINT = URI.create("http://127.0.0.1:8765/ingest/burp-history");
    private static final String ENV_ENDPOINT = "BURP_AI_REDACTION_GATEWAY_URL";

    private final URI endpoint;

    private LocalGatewayClient(URI endpoint) {
        this.endpoint = endpoint;
    }

    static LocalGatewayClient fromEnvironment() {
        String configured = System.getenv(ENV_ENDPOINT);
        if (configured == null || configured.isBlank()) {
            return new LocalGatewayClient(DEFAULT_ENDPOINT);
        }
        return new LocalGatewayClient(parseLoopbackEndpoint(configured));
    }

    HandoffResult send(List<ProxyHttpRequestResponse> items) throws IOException {
        int sent = 0;
        int skipped = 0;
        int index = 1;

        for (ProxyHttpRequestResponse item : items) {
            if (!isEligible(item)) {
                skipped += 1;
                continue;
            }

            post(buildPayload(index, item));
            sent += 1;
            index += 1;
        }

        return new HandoffResult(sent, skipped);
    }

    private boolean isEligible(ProxyHttpRequestResponse item) {
        return item != null
            && item.request() != null
            && item.request().isInScope();
    }

    private String buildPayload(int index, ProxyHttpRequestResponse item) {
        HttpResponse response = item.hasResponse() ? item.response() : null;
        String responseText = response == null ? null : response.toString();

        return "{"
            + "\"schema_version\":\"montoya-handoff-v1\","
            + "\"source\":\"burp_proxy_history\","
            + "\"source_event_id\":" + JsonStrings.quote("burp-proxy-history-" + index) + ","
            + "\"in_scope\":true,"
            + "\"raw_transport\":\"loopback_localhost\","
            + "\"raw_values_included\":true,"
            + "\"request\":" + JsonStrings.quote(item.request().toString()) + ","
            + "\"response\":" + JsonStrings.quote(responseText)
            + "}";
    }

    private void post(String payload) throws IOException {
        URL url = endpoint.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(10000);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        connection.setFixedLengthStreamingMode(bytes.length);

        try (OutputStream stream = connection.getOutputStream()) {
            stream.write(bytes);
        }

        int statusCode = connection.getResponseCode();
        if (statusCode < 200 || statusCode >= 300) {
            throw new IOException("Loopback gateway returned HTTP " + statusCode);
        }
    }

    private static URI parseLoopbackEndpoint(String value) {
        URI uri = URI.create(value);
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (!"http".equalsIgnoreCase(scheme) || host == null || !isLoopbackHost(host)) {
            throw new IllegalArgumentException(ENV_ENDPOINT + " must use an http loopback endpoint");
        }
        return uri;
    }

    private static boolean isLoopbackHost(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        return normalized.equals("127.0.0.1")
            || normalized.equals("localhost")
            || normalized.equals("::1")
            || normalized.equals("[::1]");
    }
}
