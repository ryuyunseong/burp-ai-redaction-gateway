package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import com.sun.net.httpserver.HttpServer;

import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

public final class LiveCollectorTest {
    public static void main(String[] args) throws Exception {
        AtomicInteger received = new AtomicInteger();
        AtomicReference<String> lastBody = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ingest", exchange -> {
            lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            received.incrementAndGet();
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "/ingest");
            exchange.sendResponseHeaders(307, -1);
            exchange.close();
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        try (LiveCollector live = new LiveCollector(LocalGatewayClient.fromEndpoint(base + "/ingest"))) {
            HttpRequest allowed = request("example.test", true, 100);
            InterceptedResponse response = response(allowed);
            InterceptedResponse unreadable = proxy(InterceptedResponse.class, (instance, method, arguments) -> {
                throw new IllegalStateException("unreadable fixture");
            });
            live.capture(unreadable);
            require(received.get() == 0 && live.observed() == 0 && live.failed() == 0, "disabled collector must ignore responses");
            live.start();
            live.capture(unreadable);
            require(live.observed() == 1 && live.failed() == 1, "an unreadable Proxy response must count as a failure");
            live.capture(response(request("other.test", false, 100)));
            live.capture(response(request("127.0.0.1", true, 100)));
            live.capture(response(request("example.test", true, LocalGatewayClient.MAX_PAYLOAD_BYTES + 1)));
            require(live.skipped() == 3, "scope and size exclusions");
            require(received.get() == 0, "excluded requests must not be sent");
            live.capture(response);
            await(() -> live.sent() == 1);
            assertUuidIdentifier(lastBody.get());
            require(lastBody.get().contains("montoya-handoff-v1"), "existing handoff schema required");
            String first = lastBody.get();
            live.capture(response);
            await(() -> live.sent() == 2);
            require(!first.equals(lastBody.get()), "events must not overwrite each other");
            live.stop();
            live.capture(response);
            require(received.get() == 2 && live.observed() == 6, "stopped collector must not count or send");
            ProxyHttpRequestResponse historyItem = proxy(ProxyHttpRequestResponse.class, (instance, method, arguments) -> switch (method.getName()) {
                case "request" -> allowed;
                case "response" -> response;
                case "hasResponse" -> true;
                default -> null;
            });
            LocalGatewayClient manual = LocalGatewayClient.fromEndpoint(base + "/ingest");
            manual.send(List.of(historyItem));
            String firstBatch = lastBody.get();
            assertUuidIdentifier(firstBatch);
            manual.send(List.of(historyItem));
            assertUuidIdentifier(lastBody.get());
            require(!firstBatch.equals(lastBody.get()), "manual history batches must use unique identifiers");
            require(received.get() == 4, "both manual history batches must complete");
            boolean rejected = false;
            try {
                LocalGatewayClient.fromEndpoint(base + "/redirect").sendPayload("{}");
            } catch (java.io.IOException expected) {
                rejected = true;
            }
            require(rejected && received.get() == 4, "redirects must not forward raw data");
            for (String endpoint : List.of("https://example.test/ingest", "http://example.test/ingest")) {
                try {
                    LocalGatewayClient.fromEndpoint(endpoint);
                    throw new AssertionError("non-loopback endpoint accepted");
                } catch (IllegalArgumentException expected) { }
            }
        } finally {
            server.stop(0);
        }
        testBoundedQueueAndStop();
        System.out.println("Live collector scope, queue, stop, identifiers and loopback tests passed.");
    }

    private static void testBoundedQueueAndStop() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger received = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ingest", exchange -> {
            exchange.getRequestBody().readAllBytes();
            received.incrementAndGet();
            entered.countDown();
            try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();
        try (LiveCollector live = new LiveCollector(LocalGatewayClient.fromEndpoint("http://127.0.0.1:" + server.getAddress().getPort() + "/ingest"))) {
            live.start();
            live.capture(response(request("example.test", true, 100)));
            require(entered.await(5, TimeUnit.SECONDS), "worker did not start");
            for (int index = 0; index < 20; index++) {
                live.capture(response(request("example.test", true, 100)));
            }
            require(live.skipped() == 4, "queue must be bounded to sixteen waiting items");
            live.stop();
            release.countDown();
            await(() -> live.sent() == 1);
            live.start();
            live.capture(response(request("example.test", true, 100)));
            await(() -> live.sent() == 2);
            require(received.get() == 2, "stop must discard pending raw payloads without replay");
        } finally {
            release.countDown();
            server.stop(0);
        }
    }

    private static HttpRequest request(String host, boolean inScope, int size) {
        HttpService service = proxy(HttpService.class, (instance, method, args) -> method.getName().equals("host") ? host : null);
        ByteArray bytes = proxy(ByteArray.class, (instance, method, args) -> method.getName().equals("length") ? size : null);
        return proxy(HttpRequest.class, (instance, method, args) -> switch (method.getName()) {
            case "httpService" -> service;
            case "isInScope" -> inScope;
            case "toByteArray" -> bytes;
            case "toString" -> "GET /api/profile HTTP/1.1\r\nHost: example.test\r\n\r\n";
            default -> null;
        });
    }

    private static InterceptedResponse response(HttpRequest request) {
        ByteArray bytes = proxy(ByteArray.class, (instance, method, args) -> method.getName().equals("length") ? 100 : null);
        return proxy(InterceptedResponse.class, (instance, method, args) -> switch (method.getName()) {
            case "initiatingRequest" -> request;
            case "toByteArray" -> bytes;
            case "toString" -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";
            default -> null;
        });
    }

    private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, handler));
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        require(condition.getAsBoolean(), "worker timed out");
    }

    private static void require(boolean condition, String message) {
        if (!condition) { throw new AssertionError(message); }
    }

    private static void assertUuidIdentifier(String payload) {
        Matcher field = Pattern.compile("\"source_event_id\":\"([^\"]+)\"").matcher(payload);
        require(field.find(), "source identifier must be present");
        require(UUID.fromString(field.group(1)).toString().equals(field.group(1)), "identifier must be a canonical UUID");
    }
}
