package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.io.IOException;
import java.util.List;

public final class BurpAiRedactionGatewayExtension implements BurpExtension {
    private Logging logging;
    private ScopedHistoryCollector collector;
    private LocalGatewayClient gatewayClient;

    @Override
    public void initialize(MontoyaApi api) {
        this.logging = api.logging();
        this.collector = new ScopedHistoryCollector(api.proxy());
        this.gatewayClient = LocalGatewayClient.fromEnvironment();

        api.extension().setName("Burp AI Redaction Gateway Collector");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                return BurpAiRedactionGatewayExtension.this.provideMenuItems(event);
            }
        });

        logging.logToOutput(
            "Burp AI Redaction Gateway collector loaded. Raw HTTP is not logged; handoff is loopback only."
        );
    }

    private List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem sendScopedHistory = new JMenuItem("Send scoped Proxy history to redaction gateway");
        sendScopedHistory.addActionListener(action -> sendScopedHistory());
        return List.of(sendScopedHistory);
    }

    private void sendScopedHistory() {
        try {
            List<ProxyHttpRequestResponse> scopedItems = collector.collectScopedHistory();
            HandoffResult result = gatewayClient.send(scopedItems);
            logging.logToOutput(
                "Scoped Proxy history handoff completed. items_sent="
                    + result.itemsSent()
                    + ", skipped="
                    + result.skipped()
            );
        } catch (IOException | IllegalArgumentException exception) {
            logging.logToError(
                "Scoped Proxy history handoff failed. error_type="
                    + exception.getClass().getSimpleName()
            );
        }
    }
}
