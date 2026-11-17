package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

final class LocalGatewayClient {
    static final int MAX_PAYLOAD_BYTES = 1_048_576;
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

    static LocalGatewayClient fromEndpoint(String endpoint) {
        return new LocalGatewayClient(parseLoopbackEndpoint(endpoint));
    }

    String livePayload(String eventId, HttpRequest request, HttpResponse response) {
        CollectorSafeHostMetadata decision = CollectorSafeHostMetadata.evaluateRequest(request);
        if (!decision.allowed() || response == null) {
            return null;
        }
        if ((long) request.toByteArray().length() + response.toByteArray().length() > MAX_PAYLOAD_BYTES) {
            return null;
        }
        String payload = payload(eventId, request, response, decision.host());
        return payload.getBytes(StandardCharsets.UTF_8).length <= MAX_PAYLOAD_BYTES ? payload : null;
    }

    void sendPayload(String payload) throws IOException {
        post(payload);
    }

    HandoffResult send(List<ProxyHttpRequestResponse> items) throws IOException {
        int sent = 0;
        int skipped = 0;
        int outOfScopeSkipped = 0;
        int missingHostSkipped = 0;
        int invalidHostSkipped = 0;

        for (ProxyHttpRequestResponse item : items) {
            CollectorSafeHostMetadata decision = CollectorSafeHostMetadata.evaluate(item);
            if (!decision.allowed()) {
                skipped += 1;
                if (CollectorSafeHostMetadata.REASON_OUT_OF_BURP_SCOPE.equals(decision.reason())) {
                    outOfScopeSkipped += 1;
                } else if (CollectorSafeHostMetadata.REASON_MISSING_HOST.equals(decision.reason())) {
                    missingHostSkipped += 1;
                } else if (CollectorSafeHostMetadata.REASON_INVALID_HOST.equals(decision.reason())) {
                    invalidHostSkipped += 1;
                }
                continue;
            }

            post(buildPayload(item, decision.host()));
            sent += 1;
        }

        return new HandoffResult(sent, skipped, outOfScopeSkipped, missingHostSkipped, invalidHostSkipped);
    }

    private String buildPayload(ProxyHttpRequestResponse item, String requestHost) {
        HttpResponse response = item.hasResponse() ? item.response() : null;
        return payload(UUID.randomUUID().toString(), item.request(), response, requestHost);
    }

    private String payload(String eventId, HttpRequest request, HttpResponse response, String requestHost) {
        String responseText = response == null ? null : response.toString();

        return "{"
            + "\"schema_version\":\"montoya-handoff-v1\","
            + "\"source\":\"burp_proxy_history\","
            + "\"source_event_id\":" + JsonStrings.quote(eventId) + ","
            + "\"in_scope\":true,"
            + "\"raw_transport\":\"loopback_localhost\","
            + "\"raw_values_included\":true,"
            + "\"request_metadata\":{\"host\":" + JsonStrings.quote(requestHost) + "},"
            + "\"request\":" + JsonStrings.quote(request.toString()) + ","
            + "\"response\":" + JsonStrings.quote(responseText)
            + "}";
    }

    private void post(String payload) throws IOException {
        byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("payload_too_large");
        }
        URL url = endpoint.toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(10000);
        connection.setRequestMethod("POST");
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        connection.setFixedLengthStreamingMode(bytes.length);
        try {
            try (OutputStream stream = connection.getOutputStream()) {
                stream.write(bytes);
            }
            int statusCode = connection.getResponseCode();
            if (statusCode < 200 || statusCode >= 300) {
                throw new IOException("Loopback gateway returned HTTP " + statusCode);
            }
            connection.getInputStream().close();
        } finally {
            connection.disconnect();
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
