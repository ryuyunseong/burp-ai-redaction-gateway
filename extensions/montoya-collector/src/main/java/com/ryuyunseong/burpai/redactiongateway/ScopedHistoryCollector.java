package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

import java.util.List;

final class ScopedHistoryCollector {
    private final Proxy proxy;

    ScopedHistoryCollector(Proxy proxy) {
        this.proxy = proxy;
    }

    List<ProxyHttpRequestResponse> collectScopedHistory() {
        return proxy.history(requestResponse ->
            requestResponse != null
        );
    }
}
