package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManagerCallback;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.os.Bundle;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.gson.Gson;
import com.lnikkila.oidc.OIDCAccountManager;
import com.lnikkila.oidc.security.UserNotAuthenticatedWrapperException;

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
    public static Map getJson(OIDCAccountManager accountManager, String url, Account account,
                              AccountManagerCallback<Bundle> callback)
            throws IOException, UserNotAuthenticatedWrapperException, AuthenticatorException, OperationCanceledException {

        String jsonString = makeRequest(accountManager, HttpRequest.METHOD_GET, url, account, callback);
        return new Gson().fromJson(jsonString, Map.class);
    }

    /**
     * Makes an arbitrary HTTP request using the provided account.
     *
     * If the request doesn't execute successfully on the first try, the tokens will be refreshed
     * and the request will be retried. If the second try fails, an exception will be raised.
     */
    public static String makeRequest(OIDCAccountManager accountManager, String method, String url, Account account,
                                     AccountManagerCallback<Bundle> callback)
            throws IOException, UserNotAuthenticatedWrapperException, AuthenticatorException, OperationCanceledException {

        return makeRequest(accountManager, method, url, account, true, callback);
    }

    private static String makeRequest(OIDCAccountManager accountManager, String method, String url, Account account,
                                      boolean doRetry, AccountManagerCallback<Bundle> callback)
            throws IOException, UserNotAuthenticatedWrapperException, AuthenticatorException, OperationCanceledException {


        String accessToken = accountManager.getAccessToken(account, callback);

        // Prepare an API request using the accessToken
        HttpRequest request = new HttpRequest(url, method);
        request = prepareApiRequest(request, accessToken);

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
                accountManager.invalidateAuthTokens(account);

                return makeRequest(accountManager, method, url, account, false, callback);
            } else {
                // An unrecoverable error or the renewed token didn't work either
                throw new IOException(request.code() + " " + request.message() + " " + requestContent);
            }
        }
    }

    /**
     * Prepares an arbitrary API request by injecting an ID Token into an HttpRequest. Uses an
     * external library to make my life easier, but you can modify this to use whatever in case you
     * don't like the (small) dependency.
     */
    public static HttpRequest prepareApiRequest(HttpRequest request, String idToken)
            throws IOException {

        return request.authorization("Bearer " + idToken).acceptJson();
    }
}
