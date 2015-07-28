package com.lnikkila.oidcsample;

import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;

import java.io.IOException;
import java.lang.ref.WeakReference;

public class TokensExpiredCallBack implements AccountManagerCallback<Bundle> {

    WeakReference<Context> context;
    WeakReference<TokensExpiredDialogListener> interactionListener;

    public TokensExpiredCallBack(Context context, TokensExpiredDialogListener listener){
        this.context = new WeakReference<>(context);
        this.interactionListener = new WeakReference<>(listener);
    }

    @Override
    public void run(AccountManagerFuture future) {
        try {
            final Bundle result = (Bundle) future.getResult();
            final Intent launch = (Intent) result.get(AccountManager.KEY_INTENT);

            if (context.get() != null && interactionListener.get() != null && launch != null) {
                new AlertDialog.Builder(context.get())
                        .setTitle(R.string.tokensExpiredDialogTitle)
                        .setMessage(R.string.tokensExpiredDialogMsg)
                        .setCancelable(true)
                        .setNeutralButton(R.string.tokensExpiredDialogButton, new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialogInterface, int i) {
                                interactionListener.get().onRenewTokens(launch);
                                dialogInterface.dismiss();
                            }
                        })
                        .create()
                        .show();
            }
        } catch (OperationCanceledException | IOException | AuthenticatorException e) {
            e.printStackTrace(); //FIXME: handle exception
        }
    }
}
