package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.os.Bundle;
import android.text.TextUtils;

import com.lnikkila.oidc.authenticator.AuthenticatorActivity;

/**
 * Simple utility class for storing OpenID Connect configuration. This should not be used in
 * production. If you want to hide your keys, you should obfuscate them using ProGuard (with added
 * manual obfuscation), DexGuard or something else.
 *
 * See this Stack Overflow post for some suggestions:
 * https://stackoverflow.com/a/14570989
 */
public final class Config {

    // TODO: Add the OIDC client information you received from your OIDC provider below.

    public static final String clientId = "foobar";
    public static final String clientSecret = "xyzzy";

    // This URL doesn't really have a use with native apps and basically just signifies the end
    // of the authorisation process. It doesn't have to be a real URL, but it does have to be the
    // same URL that is registered with your provider.
    public static final String redirectUrl = "app://oidcsample.lnikkila.com";
    // The `offline_access` scope enables us to request Refresh Tokens, so we don't have to ask the
    // user to authorise us again every time the tokens expire. Some providers might have an
    // `offline` scope instead. If you get an `invalid_scope` error when trying to authorise the
    // app, try changing it to `offline`.
    public static final String[] scopes = {"openid", "profile", "offline_access"};

    public static Bundle getOIDCClientOptions(){
        Bundle options =  new Bundle();
        options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID, clientId);
        options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET, clientSecret);
        options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REURL, redirectUrl);
        options.putStringArray(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES, scopes);
        options.putString(AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_FLOW_TYPE, com.lnikkila.oidc.Config.Flows.Hybrid.name());
        return options;
    }

    public static void setOIDCClientOptions(AccountManager accountManager, Account account) {
        accountManager.setUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_ID, Config.clientId);
        accountManager.setUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SECRET, Config.clientSecret);
        accountManager.setUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_REURL, Config.redirectUrl);
        accountManager.setUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_SCOPES, TextUtils.join(" ", Config.scopes));
        accountManager.setUserData(account, AuthenticatorActivity.KEY_OPT_OIDC_CLIENT_FLOW_TYPE, com.lnikkila.oidc.Config.Flows.Hybrid.name());
    }
}
