package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.Locale;
import java.util.regex.Pattern;

final class CollectorSafeHostMetadata {
    static final String REASON_IN_SCOPE = "collector_scope_in_scope";
    static final String REASON_OUT_OF_BURP_SCOPE = "collector_scope_out_of_burp_scope";
    static final String REASON_MISSING_HOST = "collector_scope_missing_host";
    static final String REASON_INVALID_HOST = "collector_scope_invalid_host";

    private static final Pattern HOST_LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(?:\\.\\d{1,3}){3}");

    private final boolean allowed;
    private final String host;
    private final String reason;

    private CollectorSafeHostMetadata(boolean allowed, String host, String reason) {
        this.allowed = allowed;
        this.host = host;
        this.reason = reason;
    }

    static CollectorSafeHostMetadata evaluate(ProxyHttpRequestResponse item) {
        if (item == null || item.request() == null) {
            return skip(REASON_MISSING_HOST);
        }

        HttpRequest request = item.request();
        if (!request.isInScope()) {
            return skip(REASON_OUT_OF_BURP_SCOPE);
        }

        String host = normalizeHost(safeHttpServiceHost(request));
        if (host.isEmpty()) {
            return skip(REASON_MISSING_HOST);
        }
        if (!isValidHost(host)) {
            return skip(REASON_INVALID_HOST);
        }
        return new CollectorSafeHostMetadata(true, host, REASON_IN_SCOPE);
    }

    boolean allowed() {
        return allowed;
    }

    String host() {
        return host;
    }

    String reason() {
        return reason;
    }

    private static CollectorSafeHostMetadata skip(String reason) {
        return new CollectorSafeHostMetadata(false, "", reason);
    }

    private static String safeHttpServiceHost(HttpRequest request) {
        try {
            if (request.httpService() == null || request.httpService().host() == null) {
                return "";
            }
            return request.httpService().host();
        } catch (RuntimeException exception) {
            return "";
        }
    }

    private static String normalizeHost(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean isValidHost(String host) {
        if (host.isEmpty() || host.length() > 253) {
            return false;
        }
        if (host.contains("/") || host.contains("\\") || host.contains("?") || host.contains("#") || host.contains("@")) {
            return false;
        }
        if (host.contains(":") || host.contains("*") || containsControlOrSpace(host)) {
            return false;
        }
        if (host.equals("localhost") || host.endsWith(".localhost") || IPV4_LITERAL.matcher(host).matches()) {
            return false;
        }

        String[] labels = host.split("\\.");
        if (labels.length == 0) {
            return false;
        }
        for (String label : labels) {
            if (!HOST_LABEL.matcher(label).matches()) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsControlOrSpace(String value) {
        for (int index = 0; index < value.length(); index += 1) {
            char current = value.charAt(index);
            if (Character.isWhitespace(current) || Character.isISOControl(current)) {
                return true;
            }
        }
        return false;
    }
}
