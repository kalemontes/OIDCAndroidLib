package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.content.Context;
import android.os.Bundle;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;
import com.lnikkila.oidc.AccountUtils;
import com.lnikkila.oidc.OIDCUtils;
import com.lnikkila.oidc.authenticator.Authenticator;

import java.io.IOException;
import java.util.Map;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;
import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static java.net.HttpURLConnection.HTTP_UNAUTHORIZED;

/**
 * An incomplete class that illustrates how to make API requests with the Access Token.
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
public class APIUtility {

    /**
     * Makes a GET request and parses the received JSON string as a Map.
     */
    public static Map getJson(Context context, String url, Account account,
                              AccountManagerCallback<Bundle> callback)
            throws IOException {

        String jsonString = makeRequest(context, HttpRequest.METHOD_GET, url, account, callback);
        return new Gson().fromJson(jsonString, Map.class);
    }

    /**
     * Makes an arbitrary HTTP request using the provided account.
     *
     * If the request doesn't execute successfully on the first try, the tokens will be refreshed
     * and the request will be retried. If the second try fails, an exception will be raised.
     */
    public static String makeRequest(Context context, String method, String url, Account account,
                                     AccountManagerCallback<Bundle> callback)
            throws IOException {

        return makeRequest(context, method, url, account, true, callback);
    }

    private static String makeRequest(final Context context, String method, String url, Account account,
                                      boolean doRetry, AccountManagerCallback<Bundle> callback)
            throws IOException {

        AccountManager accountManager = AccountManager.get(context);
        String accessToken = AccountUtils.requestAccessToken(account, doRetry, callback, accountManager);

        // Prepare an API request using the accessToken
        HttpRequest request = new HttpRequest(url, method);
        request = OIDCUtils.prepareApiRequest(request, accessToken);

        if (request.ok()) {
            return request.body();
        } else {
            int code = request.code();

            String requestContent = "empty body";
            try {
                requestContent = request.body();
            } catch (HttpRequest.HttpRequestException e) {
                //Nothing to do, the response has no body or couldn't fetch it
                e.printStackTrace();
            }

            if (doRetry && (code == HTTP_UNAUTHORIZED || code == HTTP_FORBIDDEN ||
                    (code == HTTP_BAD_REQUEST && (requestContent.contains("invalid_grant") || requestContent.contains("Access Token not valid"))))) {
                // We're being denied access on the first try, let's renew the token and retry
                String accountType = context.getString(R.string.account_authenticator_type);

                accountManager.setAuthToken(account, Authenticator.TOKEN_TYPE_ID, null);
                accountManager.invalidateAuthToken(accountType, accessToken);

                return makeRequest(context, method, url, account, false, callback);
            } else {
                // An unrecoverable error or the renewed token didn't work either
                throw new IOException(request.code() + " " + request.message() + " " + requestContent);
            }
        }
    }
}
