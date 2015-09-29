package com.lnikkila.oidc;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.lnikkila.oidc.authenticator.Authenticator;

import java.io.IOException;

/**
 * A layer of syntactic sugar around the AccountManager and the Accounts.
 *
 * @author Camilo Montes
 */
public class AccountUtils {

    public static Account getAccountById(Account[] accounts, String name)  {
        if(TextUtils.isEmpty(name))
        {
            return accounts[0];
        }
        else {
            for (Account account : accounts) {
                if (TextUtils.equals(account.name, name)) {
                    return account;
                }
            }
        }
        return null;
    }

    public static String[] getAccountsName(Account[] accounts) {
        String[] names = new String[accounts.length];
        int index = 0;
        for (Account account : accounts) {
            names[index] = account.name;
            index++;
        }
        return names;
    }

    @SuppressWarnings("deprecation")
    public static String requestAccessToken(Account account, boolean doRetry,
                                            AccountManagerCallback<Bundle> callback,
                                            AccountManager accountManager) throws IOException {
        String accessToken;

        // Try retrieving an access token from the account manager. The boolean true in the invocation
        // tells Android to show a notification if the token can't be retrieved. When the
        // notification is selected, it will launch the intent for re-authorisation. You could
        // launch it automatically here if you wanted to by grabbing the intent from the bundle.
        try {

            AccountManagerFuture<Bundle> futureManager;

            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
                if (doRetry) {
                    futureManager = accountManager.getAuthToken(account,
                            Authenticator.TOKEN_TYPE_ACCESS, false, null, null);
                }
                else {
                    futureManager = accountManager.getAuthToken(account,
                            Authenticator.TOKEN_TYPE_ACCESS, true, callback, null);
                }
            }
            else {
                if (doRetry) {
                    futureManager = accountManager.getAuthToken(account,
                            Authenticator.TOKEN_TYPE_ACCESS, null, false, null, null);
                } else {
                    futureManager = accountManager.getAuthToken(account,
                            Authenticator.TOKEN_TYPE_ACCESS, null, true, callback, null);
                }
            }
            accessToken = futureManager.getResult().getString(AccountManager.KEY_AUTHTOKEN);
        } catch (Exception e) {
            throw new IOException("Could not get access token from account.", e);
        }
        return accessToken;
    }

    public static void saveTokens(AccountManager accountManager, Account account, IdTokenResponse tokenResponse) {
        accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_ID, tokenResponse.getIdToken());
        accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_ACCESS, tokenResponse.getAccessToken());
        accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_REFRESH, tokenResponse.getRefreshToken());
    }

    public static void saveTokens(AccountManager accountManager, Account account, TokenResponse tokenResponse) {
        accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_ACCESS, tokenResponse.getAccessToken());
        accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_REFRESH, tokenResponse.getRefreshToken());
    }
}
