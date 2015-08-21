package com.lnikkila.oidc.authenticator;

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Log;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.oauth2.TokenResponseException;
import com.lnikkila.oidc.AccountUtils;
import com.lnikkila.oidc.Config;
import com.lnikkila.oidc.OIDCUtils;

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

    private Context context;
    private AccountManager accountManager;

    public static final String TOKEN_TYPE_ID = "com.lnikkila.oidcsample.TOKEN_TYPE_ID";
    public static final String TOKEN_TYPE_ACCESS = "com.lnikkila.oidcsample.TOKEN_TYPE_ACCESS";
    public static final String TOKEN_TYPE_REFRESH = "com.lnikkila.oidcsample.TOKEN_TYPE_REFRESH";

    public Authenticator(Context context) {
        super(context);
        this.context = context;

        accountManager = AccountManager.get(context);

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

        Intent intent = createIntentForAuthorization(response, options);

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

        // Enables pre-ICS support.
        if(options == null || options.isEmpty()) {
            Log.i(TAG, "Trying to load OIDC client options from UserData");
            options = OIDCOptionsFromUserData(account);
        }
        else {
            Log.i(TAG, "OIDC client options where on request call");
            Log.d(TAG, options.toString());
        }

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

                Intent intent = createIntentForAuthorization(response, options);

                // Provide the account that we need re-authorised
                intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_OBJECT, account);

                result.putParcelable(AccountManager.KEY_INTENT, intent);
                return result;
            } else {
                // Got a refresh token, let's use it to get a fresh set of tokens
                Log.d(TAG, "Got refresh token, getting new tokens.");

                try {
                    refreshTokens(account, refreshToken, options);
                }
                catch (TokenResponseException e) {
                    // If the refresh token has expired, we need to launch an intent for the user
                    // to get us a new set of tokens by authorising us again.

                    Log.d(TAG, "Refresh token expired, launching intent for renewing authorisation.");

                    Bundle result = new Bundle();

                    Intent intent = createIntentForAuthorization(response, options);

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
     * @param options contains the OIDC client options (clientId, clientSecret, redirectUrl, scopes)
     * @throws TokenResponseException when refreshToken is invalid or expired
     */
    private void refreshTokens(Account account, String refreshToken, Bundle options) throws TokenResponseException {
        try {
            if (options != null) {
                if (options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID) &&
                        options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET) &&
                        options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES)) {
                    //The OIDC client options are correctly set.
                    Log.d(TAG, "The OIDC client options are correctly set.");

                    String clientId = options.getString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID);
                    String clientSecret = options.getString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET);
                    String[] scopes = options.getStringArray(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES);
                    String realm = options.getString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REALM);

                    TokenResponse tokenResponse = OIDCUtils.refreshTokens(Config.tokenServerUrl,
                            realm,
                            clientId,
                            clientSecret,
                            scopes,
                            refreshToken);

                    Log.d(TAG, "Got new tokens.");
                    AccountUtils.saveTokens(accountManager, account, tokenResponse);
                }
                else {
                    //The OIDC client options are not correctly set.
                    //This usually means that the app using the lib didn't set them as it should when making an explicit call to authenticator.
                    throw new IOException("Missing OIDC client configuration");
                }
            }
            else {
                // The OIDC client options are NOT set.
                // This case usually happends when trying to renew token via Android's system settings (Sync).
                //TODO: see what we can do here
                throw new IOException("OIDC client configuration is not set");
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
     * @param options contains the OIDC client options (clientId, clientSecret, redirectUrl, scopes)
     * @return an intent to open AuthenticatorActivity with AuthenticatorActivity.KEY_PRESENT_OPTS_FORM extra
     * set to false if OIDC client correctly options are set (true otherwise).
     */
    private Intent createIntentForAuthorization(AccountAuthenticatorResponse response, Bundle options) {
        Intent intent = new Intent(context, AuthenticatorActivity.class);

        if (options != null) {
            intent.putExtras(options);

            if (options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID) &&
                    options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET) &&
                    options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REURL) &&
                    options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES) &&
                    options.containsKey(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_FLOW_TYPE)) {
                //The OIDC client options are correctly set.
                Log.d(TAG, "The OIDC client options are correctly set.");

                //This means we will be able to created authorisation URL directly.
                intent.putExtra(AuthenticatorActivity.KEY_PRESENT_OPTS_FORM, false);
            }
            else {
                //The OIDC client options are not correctly set.
                //This usually means that the app using the lib didn't set them as it should when making an explicit call to authenticator.
                Log.w(TAG, "Some OIDC client options are missing. Using form intent option so user can set them.");

                //The user will have to set them via the form that will be presented on the AuthenticatorActivity.
                intent.putExtra(AuthenticatorActivity.KEY_PRESENT_OPTS_FORM, true);
            }
        }
        else {
            // The OIDC client options are NOT set.
            // This case usually happends when the user adds a new account through Android's system settings.
            Log.d(TAG, "The OIDC client options are not set. Using form intent option so user can set them.");

            //The user will have to set them via the form that will be presented on the AuthenticatorActivity.
            intent.putExtra(AuthenticatorActivity.KEY_PRESENT_OPTS_FORM, true);
        }

        intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);

        return intent;
    }

    /**
     * <p>
     *     Fetches OIDC options that are store in the account UserData and returns them in a bundle.
     * </p>
     * <p>
     *      <b>This is needed to enable pre-ICS support.</b>
     *      Apps can call the AccountManager using the deprecated method
     *      {@link AccountManager#getAuthToken(Account, String, boolean, AccountManagerCallback, Handler)}
     *      to request tokens. Before doing this they have to ensure that this options were set as UserData
     *      on account creation.
     * </p>
     * <p>
     *     {@link AccountManager#getAuthToken(Account, String, Bundle, boolean, AccountManagerCallback, Handler)}
     *     should be ALWAYS use for post-ICS passing the options as parameter and not setting any UserData
     *     on account creation.
     * </p>
     * @param account the account where the options are saved
     * @return OIDC options as a bundle or null if the options were NOT correctly set on account creation.
     */
    private Bundle OIDCOptionsFromUserData(Account account) {
        String clientId = accountManager.getUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID);
        String clientSecret = accountManager.getUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET);
        String redirectUrl = accountManager.getUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REURL);
        String scopesAsString = accountManager.getUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES);
        String[] scopes = scopesAsString != null ? TextUtils.split(scopesAsString, " ") : null;
        String realm = accountManager.getUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REALM);

        Bundle options = null;
        if(!TextUtils.isEmpty(clientId) && !TextUtils.isEmpty(clientSecret) && !TextUtils.isEmpty(redirectUrl) && scopes != null) {
            options =  new Bundle();
            options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID, clientId);
            options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET, clientSecret);
            options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REURL, redirectUrl);
            options.putStringArray(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES, scopes);
            options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REALM, realm);
        }

        return options;
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
