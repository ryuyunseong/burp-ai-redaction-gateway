package com.ryuyunseong.burpai.redactiongateway;

record HandoffResult(
    int itemsSent,
    int skipped,
    int outOfScopeSkipped,
    int missingHostSkipped,
    int invalidHostSkipped
) {
}
