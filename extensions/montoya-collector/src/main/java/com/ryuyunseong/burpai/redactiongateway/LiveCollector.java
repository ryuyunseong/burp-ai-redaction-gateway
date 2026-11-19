package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.proxy.http.InterceptedResponse;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

final class LiveCollector implements AutoCloseable {
    private final LocalGatewayClient client;
    private final ThreadPoolExecutor worker;
    private final AtomicLong observed = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong skipped = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private volatile String session;

    LiveCollector(LocalGatewayClient client) {
        this.client = client;
        worker = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(16), task -> {
            Thread thread = new Thread(task, "burp-local-redaction");
            thread.setDaemon(true);
            return thread;
        });
    }

    synchronized void start() {
        if (session == null && !worker.isShutdown()) {
            session = UUID.randomUUID().toString();
        }
    }

    synchronized void stop() {
        session = null;
        worker.getQueue().clear();
    }

    boolean running() { return session != null; }
    long observed() { return observed.get(); }
    long sent() { return sent.get(); }
    long skipped() { return skipped.get(); }
    long failed() { return failed.get(); }

    void capture(InterceptedResponse response) {
        String activeSession = session;
        if (activeSession == null) {
            return;
        }
        observed.incrementAndGet();
        try {
            String payload = client.livePayload(UUID.randomUUID().toString(), response.initiatingRequest(), response);
            if (payload == null) {
                skipped.incrementAndGet();
                return;
            }
            synchronized (this) {
                if (!activeSession.equals(session)) {
                    return;
                }
                worker.execute(() -> {
                    if (!activeSession.equals(session)) {
                        return;
                    }
                    try {
                        client.sendPayload(payload);
                        sent.incrementAndGet();
                    } catch (IOException | RuntimeException exception) {
                        failed.incrementAndGet();
                    }
                });
            }
        } catch (RejectedExecutionException exception) {
            skipped.incrementAndGet();
        } catch (RuntimeException exception) {
            failed.incrementAndGet();
        }
    }

    @Override
    public synchronized void close() {
        stop();
        worker.shutdownNow();
    }
}
