package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

public final class CollectorSafeHostMetadataMatrixTest {
    private record MatrixCase(
        String name,
        String host,
        boolean burpInScope,
        boolean expectedAllowed,
        String expectedReason,
        String expectedHost
    ) {
    }

    private static final List<MatrixCase> CASES = List.of(
        new MatrixCase("normal_host", "example.test", true, true, "collector_scope_in_scope", "example.test"),
        new MatrixCase("uppercase_host", "EXAMPLE.TEST", true, true, "collector_scope_in_scope", "example.test"),
        new MatrixCase("trailing_dot_host", "example.test.", true, true, "collector_scope_in_scope", "example.test."),
        new MatrixCase("url_shape", "https://example.test", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("path_query_shape", "example.test/path?debug=1", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("wildcard_host", "*.example.test", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("localhost_name", "localhost", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("loopback_ipv4", "127.0.0.1", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("ip_literal", "203.0.113.10", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("private_looking_ip", "10.0.0.1", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("malformed_label", "-example.test", true, false, "collector_scope_invalid_host", ""),
        new MatrixCase("lookalike_suffix", "example.test.evil.test", false, false, "collector_scope_out_of_burp_scope", ""),
        new MatrixCase("subdomain", "api.example.test", true, true, "collector_scope_in_scope", "api.example.test"),
        new MatrixCase("out_of_scope_host", "other.test", false, false, "collector_scope_out_of_burp_scope", "")
    );

    private CollectorSafeHostMetadataMatrixTest() {
    }

    public static void main(String[] args) {
        for (MatrixCase testCase : CASES) {
            assertDecision(testCase, CollectorSafeHostMetadata.evaluate(item(testCase.host(), testCase.burpInScope())));
        }

        assertDecision(
            new MatrixCase("null_item", "", true, false, "collector_scope_missing_host", ""),
            CollectorSafeHostMetadata.evaluate(null)
        );
        assertDecision(
            new MatrixCase("null_request", "", true, false, "collector_scope_missing_host", ""),
            CollectorSafeHostMetadata.evaluate(nullRequestItem())
        );
        assertDecision(
            new MatrixCase("http_service_exception", "", true, false, "collector_scope_missing_host", ""),
            CollectorSafeHostMetadata.evaluate(itemWithThrowingService())
        );
    }

    private static void assertDecision(MatrixCase testCase, CollectorSafeHostMetadata decision) {
        if (decision.allowed() != testCase.expectedAllowed()) {
            throw new AssertionError(testCase.name() + " allowed mismatch");
        }
        if (!decision.reason().equals(testCase.expectedReason())) {
            throw new AssertionError(testCase.name() + " reason mismatch: " + decision.reason());
        }
        if (!decision.host().equals(testCase.expectedHost())) {
            throw new AssertionError(testCase.name() + " host normalization mismatch");
        }
    }

    private static ProxyHttpRequestResponse item(String host, boolean inScope) {
        HttpRequest request = request(host, inScope);
        InvocationHandler handler = (proxy, method, args) -> {
            if ("request".equals(method.getName())) {
                return request;
            }
            return defaultReturn(method);
        };
        return proxy(ProxyHttpRequestResponse.class, handler);
    }

    private static ProxyHttpRequestResponse nullRequestItem() {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("request".equals(method.getName())) {
                return null;
            }
            return defaultReturn(method);
        };
        return proxy(ProxyHttpRequestResponse.class, handler);
    }

    private static ProxyHttpRequestResponse itemWithThrowingService() {
        HttpRequest request = requestWithThrowingService();
        InvocationHandler handler = (proxy, method, args) -> {
            if ("request".equals(method.getName())) {
                return request;
            }
            return defaultReturn(method);
        };
        return proxy(ProxyHttpRequestResponse.class, handler);
    }

    private static HttpRequest request(String host, boolean inScope) {
        HttpService service = service(host);
        InvocationHandler handler = (proxy, method, args) -> {
            if ("isInScope".equals(method.getName())) {
                return inScope;
            }
            if ("httpService".equals(method.getName())) {
                return service;
            }
            return defaultReturn(method);
        };
        return proxy(HttpRequest.class, handler);
    }

    private static HttpRequest requestWithThrowingService() {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("isInScope".equals(method.getName())) {
                return true;
            }
            if ("httpService".equals(method.getName())) {
                throw new IllegalStateException("synthetic service failure");
            }
            return defaultReturn(method);
        };
        return proxy(HttpRequest.class, handler);
    }

    private static HttpService service(String host) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("host".equals(method.getName())) {
                return host;
            }
            return defaultReturn(method);
        };
        return proxy(HttpService.class, handler);
    }

    private static Object defaultReturn(Method method) {
        Class<?> returnType = method.getReturnType();
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType == int.class) {
            return 0;
        }
        if (returnType == String.class) {
            return "";
        }
        return null;
    }

    private static <T> T proxy(Class<T> type, InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, handler));
    }
}
