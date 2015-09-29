package com.lnikkila.oidc.authenticator;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.lnikkila.oidc.AccountUtils;
import com.lnikkila.oidc.OIDCUtils;
import com.lnikkila.oidc.R;

import java.io.IOException;

import static java.net.HttpURLConnection.HTTP_BAD_REQUEST;

/**
 * Used by Android's AccountManager to manage our account information.
 *
 * The three OpenID tokens (not counting the single-use Authorization Token that is discarded) are
 * stored as what Android calls "auth tokens". They all have different token types:
 *
 * ID Token:      TOKEN_TYPE_ID
 * Access Token:  TOKEN_TYPE_ACCESS  (replaceable by the ID Token, so we're not really using this)
 * Refresh Token: TOKEN_TYPE_REFRESH
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
public class Authenticator extends AbstractAccountAuthenticator {

    private final String TAG = getClass().getSimpleName();

    protected final Context context;
    protected final AccountManager accountManager;

    protected final String tokenEndpoint;

    protected final String clientId;
    protected final String clientSecret;
    protected final String redirectUrl;
    protected final String[] scopes;
    protected final String flowType;

    public static final String TOKEN_TYPE_ID = "com.lnikkila.oidcsample.TOKEN_TYPE_ID";
    public static final String TOKEN_TYPE_ACCESS = "com.lnikkila.oidcsample.TOKEN_TYPE_ACCESS";
    public static final String TOKEN_TYPE_REFRESH = "com.lnikkila.oidcsample.TOKEN_TYPE_REFRESH";

    public Authenticator(Context context) {
        super(context);
        this.context = context;

        this.accountManager = AccountManager.get(context);

        this.tokenEndpoint = this.context.getString(R.string.op_tokenEndpoint);

        this.clientId      = this.context.getString(R.string.oidc_clientId);
        this.clientSecret  = this.context.getString(R.string.oidc_clientSecret);
        this.redirectUrl   = this.context.getString(R.string.oidc_redirectUrl);
        this.scopes        = this.context.getResources().getStringArray(R.array.oidc_scopes);
        this.flowType      = this.context.getString(R.string.oidc_flowType);

        Log.d(TAG, "Authenticator created.");
    }

    /**
     * Called when the user adds a new account through Android's system settings or when an app
     * explicitly calls this.
     */
    @Override
    public Bundle addAccount(AccountAuthenticatorResponse response, String accountType,
                             String authTokenType, String[] requiredFeatures, Bundle options) {

        Log.d(TAG, String.format("addAccount called with accountType %s, authTokenType %s.",
                accountType, authTokenType));

        Bundle result = new Bundle();

        Intent intent = createIntentForAuthorization(response);

        // We're creating a new account, not just renewing our authorisation
        intent.putExtra(AuthenticatorActivity.KEY_IS_NEW_ACCOUNT, true);

        result.putParcelable(AccountManager.KEY_INTENT, intent);

        return result;
    }

    /**
     * Tries to retrieve a previously stored token of any type. If the token doesn't exist yet or
     * has been invalidated, we need to request a set of replacement tokens.
     */
    @Override
    public Bundle getAuthToken(AccountAuthenticatorResponse response, Account account,
                               String authTokenType, Bundle options) {

        Log.d(TAG, String.format("getAuthToken called with account.type '%s', account.name '%s', " +
                "authTokenType '%s'.", account.type, account.name, authTokenType));

        // Try to retrieve a stored token
        String token = accountManager.peekAuthToken(account, authTokenType);

        if (TextUtils.isEmpty(token)) {
            // If we don't have one or the token has been invalidated, we need to check if we have
            // a refresh token
            Log.d(TAG, "Token empty, checking for refresh token.");
            String refreshToken = accountManager.peekAuthToken(account, TOKEN_TYPE_REFRESH);

            if (TextUtils.isEmpty(refreshToken)) {
                // If we don't even have a refresh token, we need to launch an intent for the user
                // to get us a new set of tokens by authorising us again.

                Log.d(TAG, "Refresh token empty, launching intent for renewing authorisation.");

                Bundle result = new Bundle();

                Intent intent = createIntentForAuthorization(response);

                // Provide the account that we need re-authorised
                intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_OBJECT, account);

                result.putParcelable(AccountManager.KEY_INTENT, intent);
                return result;
            } else {
                // Got a refresh token, let's use it to get a fresh set of tokens
                Log.d(TAG, "Got refresh token, getting new tokens.");

                try {
                    refreshTokens(account, refreshToken);
                }
                catch (TokenResponseException e) {
                    // If the refresh token has expired, we need to launch an intent for the user
                    // to get us a new set of tokens by authorising us again.

                    Log.d(TAG, "Refresh token expired, launching intent for renewing authorisation.");

                    Bundle result = new Bundle();

                    Intent intent = createIntentForAuthorization(response);

                    // Provide the account that we need re-authorised
                    intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_OBJECT, account);

                    result.putParcelable(AccountManager.KEY_INTENT, intent);
                    return result;
                }

                // Now, let's return the token that was requested
                token = accountManager.peekAuthToken(account, authTokenType);
            }
        }

        Log.d(TAG, String.format("Returning token '%s' of type '%s'.", token, authTokenType));

        Bundle result = new Bundle();

        result.putString(AccountManager.KEY_ACCOUNT_NAME, account.name);
        result.putString(AccountManager.KEY_ACCOUNT_TYPE, account.type);
        result.putString(AccountManager.KEY_AUTHTOKEN, token);

        return result;
    }

    /**
     * Refreshes all account tokens by requesting new tokens to the access_token endpoint using the given refreshToken.
     * @param account the account whose token should be refreshed, will never be null
     * @param refreshToken the refresh token to be use
     * @throws TokenResponseException when refreshToken is invalid or expired
     */
    protected void refreshTokens(Account account, String refreshToken) throws TokenResponseException {
        try {
            if (checkOIDCClientConfiguration(clientId, clientSecret, redirectUrl, scopes, flowType)) {
                Log.d(TAG, "The OIDC client options are correctly set.");

                TokenResponse tokenResponse = OIDCUtils.refreshTokens(
                        tokenEndpoint, clientId, clientSecret, scopes, refreshToken);

                Log.d(TAG, "Got new tokens.");
                AccountUtils.saveTokens(accountManager, account, tokenResponse);
            }
            else {
                // The OIDC client options are NOT set.
                Log.e(TAG, "OIDC client options are missing or not correctly set");
                throw new IOException("OIDC client options are missing or not correctly set");
            }
        }
        catch (TokenResponseException e) {
            //If token has expired propagate the exception, else just treat it like an IOException
            if(e.getStatusCode() == HTTP_BAD_REQUEST && e.getContent().contains("invalid_grant")) {
                Log.d(TAG, "Refresh token expired response detected");
                throw e; //TODO: maybe we should make a custom exception class to handle this?
            }
            else {
                // There's not much we can do if we get here
                Log.e(TAG, "Couldn't get new tokens.", e);
            }
        }
        catch (IOException e) {
            // There's not much we can do if we get here
            Log.e(TAG, "Couldn't get new tokens.", e);
        }
    }

    /**
     * Create an intent for showing the authorisation web page.
     * @param response response to send the result back to the AccountManager, will never be null
     * @return an intent to open AuthenticatorActivity with AuthenticatorActivity.KEY_PRESENT_OPTS_FORM extra
     * set to false if OIDC client correctly options are set (true otherwise).
     */
    protected Intent createIntentForAuthorization(AccountAuthenticatorResponse response) {
        Intent intent = null;

        if (checkOIDCClientConfiguration(clientId, clientSecret, redirectUrl, scopes, flowType)) {
            intent = new Intent(context, AuthenticatorActivity.class);
            intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
        }
        else {
            Log.e(TAG, "OIDC client options are missing or not correctly set");
        }

        return intent;
    }

    /**
     * Checks if OIDC client settings are correctly set.
     * @return true if all expected settings are set, false otherwise.
     */
    protected boolean checkOIDCClientConfiguration(String clientId, String clientSecret, String redirectUrl, String[] scopes, String flowType) {
        return !TextUtils.isEmpty(clientId) && !TextUtils.isEmpty(clientSecret) &&
                !TextUtils.isEmpty(redirectUrl) && scopes.length > 0 &&
                !TextUtils.isEmpty(flowType) && OIDCUtils.isSupportedFlow(flowType);
    }

    @Override
    public String getAuthTokenLabel(String authTokenType) {
        return null;
    }

    @Override
    public Bundle hasFeatures(AccountAuthenticatorResponse response, Account account,
                              String[] features) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
        return null;
    }

    @Override
    public Bundle confirmCredentials(AccountAuthenticatorResponse response, Account account,
                                     Bundle options) throws NetworkErrorException {
        return null;
    }

    @Override
    public Bundle updateCredentials(AccountAuthenticatorResponse response, Account account,
                                    String authTokenType, Bundle options)
                                    throws NetworkErrorException {
        return null;
    }

}
