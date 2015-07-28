package com.lnikkila.oidcsample;

import android.content.Intent;

public interface TokensExpiredDialogListener {
    void onRenewTokens(Intent renewIntent);
    void onDoNotRevewTokens();
}
