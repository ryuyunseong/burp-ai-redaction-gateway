package com.ryuyunseong.burpai.redactiongateway;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
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
        LiveCollector live = new LiveCollector(gatewayClient);
        Timer statusTimer = new Timer(1000, null);
        api.userInterface().registerSuiteTab("로컬 보안 점검", livePanel(live, statusTimer));
        api.proxy().registerResponseHandler(new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
                return ProxyResponseReceivedAction.continueWith(response, response.annotations());
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
                try {
                    live.capture(response.initiatingRequest(), response);
                } catch (RuntimeException exception) {
                    logging.logToError("자동 수집 중 응답을 읽지 못했습니다. 원문은 기록하지 않습니다.");
                }
                return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
            }
        });
        api.extension().registerUnloadingHandler(() -> { statusTimer.stop(); live.close(); });

        api.extension().setName("Burp AI Redaction Gateway Collector");
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                return BurpAiRedactionGatewayExtension.this.provideMenuItems(event);
            }
        });

        logging.logToOutput(
            "수집기를 불러왔습니다. 자동 수집은 꺼져 있으며, 원문은 로그에 남기지 않습니다."
        );
    }

    private JPanel livePanel(LiveCollector live, Timer timer) {
        JPanel panel = new JPanel(new BorderLayout(12, 12));
        panel.add(new JLabel("<html>점검 범위에 등록한 새 Proxy 응답을 내 컴퓨터에서 마스킹합니다.<br>"
            + "이전에 쌓인 기록은 자동으로 보내지 않습니다. AI로 자동 전송하지 않습니다.<br>"
            + "먼저 로컬 도구에서 capture 명령을 실행한 뒤 시작하세요.</html>"), BorderLayout.NORTH);
        JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton start = new JButton("자동 수집 시작");
        JButton stop = new JButton("중지");
        JLabel status = new JLabel("중지됨");
        start.addActionListener(action -> live.start());
        stop.addActionListener(action -> live.stop());
        controls.add(start);
        controls.add(stop);
        controls.add(status);
        panel.add(controls, BorderLayout.CENTER);
        panel.add(new JLabel("제외: 범위 밖·잘못된 호스트·용량 초과·대기열 초과. 중지 시 진행 중인 1건은 완료될 수 있습니다."), BorderLayout.SOUTH);
        timer.addActionListener(action -> {
            start.setEnabled(!live.running());
            stop.setEnabled(live.running());
            status.setText((live.running() ? "수집 중" : "중지됨") + " · 전송 " + live.sent()
                + " · 제외 " + live.skipped() + " · 실패 " + live.failed());
        });
        timer.start();
        return panel;
    }

    private List<Component> provideMenuItems(ContextMenuEvent event) {
        JMenuItem sendScopedHistory = new JMenuItem("점검 범위의 Proxy 기록을 로컬 도구로 보내기");
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
                    + ", out_of_scope_skipped="
                    + result.outOfScopeSkipped()
                    + ", missing_host_skipped="
                    + result.missingHostSkipped()
                    + ", invalid_host_skipped="
                    + result.invalidHostSkipped()
            );
        } catch (IOException | IllegalArgumentException exception) {
            logging.logToError(
                "Scoped Proxy history handoff failed. error_type="
                    + exception.getClass().getSimpleName()
            );
        }
    }
}
