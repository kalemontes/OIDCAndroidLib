package com.lnikkila.oidc.authenticator;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.support.design.widget.TextInputLayout;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.json.gson.GsonFactory;
import com.lnikkila.oidc.AccountUtils;
import com.lnikkila.oidc.Config;
import com.lnikkila.oidc.OIDCUtils;
import com.lnikkila.oidc.R;
import com.lnikkila.oidc.minsdkcompat.CompatUri;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * An Activity that is launched by the Authenticator for requesting authorisation from the user and
 * creating an Account.
 *
 * The user will interact with the OIDC server via a WebView that monitors the URL for parameters
 * that indicate either a successful authorisation or an error. These parameters are set by the
 * spec.
 *
 * After the Authorization Token has successfully been obtained, we use the single-use token to
 * fetch an ID Token, an Access Token and a Refresh Token. We create an Account and persist these
 * tokens.
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
public class AuthenticatorActivity extends AccountAuthenticatorActivity {

    private final String TAG = getClass().getSimpleName();

    public static final String KEY_PRESENT_OPTS_FORM = "com.lnikkila.oidcsample.KEY_PRESENT_OPTS_FORM";
    public static final String KEY_IS_NEW_ACCOUNT = "com.lnikkila.oidcsample.KEY_IS_NEW_ACCOUNT";
    public static final String KEY_ACCOUNT_OBJECT = "com.lnikkila.oidcsample.KEY_ACCOUNT_OBJECT";

    public static final String KEY_OPT_OIDC_CLIENT_ID        = "clientId";
    public static final String KEY_OPT_OIDC_CLIENT_SECRET    = "clientSecret";
    public static final String KEY_OPT_OIDC_CLIENT_REURL     = "redirectUrl";
    public static final String KEY_OPT_OIDC_CLIENT_SCOPES    = "scopes";
    public static final String KEY_OPT_OIDC_CLIENT_REALM     = "realm";
    public static final String KEY_OPT_OIDC_CLIENT_FLOW_TYPE = "flowType";

    private AccountManager accountManager;
    private Account account;
    private boolean isNewAccount;

    /*package*/ WebView webView;
    /*package*/ View clientFormLayout;
    /*package*/ TextInputLayout clientIdInputLayout;
    /*package*/ TextInputLayout clientSecretInputLayout;
    /*package*/ TextInputLayout redirectUriInputLayout;
    /*package*/ TextInputLayout scopesInputLayout;
    /*package*/ Button validateClientButton;

    private String clientId;
    private String clientSecret;
    private String redirectUrl;
    private String[] scopes;
    private String realm;
    private Config.Flows flowType;
    private Spinner flowTypeSpinner;

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authentication);

        accountManager = AccountManager.get(this);

        Bundle extras = getIntent().getExtras();

        // Are we supposed to create a new account or renew the authorisation of an old one?
        isNewAccount = extras.getBoolean(KEY_IS_NEW_ACCOUNT, false);

        // In case we're renewing authorisation, we also got an Account object that we're supposed
        // to work with.
        account = extras.getParcelable(KEY_ACCOUNT_OBJECT);

        // In case that the needed OIDC options are not set, present form to set them in order to create the authentication URL
        boolean needsOptionsForm = extras.getBoolean(KEY_PRESENT_OPTS_FORM, true);

        // Initialise the WebView
        webView = (WebView) findViewById(R.id.WebView);

        //NOTE: Enable this if your authorisation page requires JavaScript
        webView.getSettings().setJavaScriptEnabled(true);

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String urlString, Bitmap favicon) {
                super.onPageStarted(view, urlString, favicon);

                Uri url = Uri.parse(urlString);

                Set<String> parameterNames;
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                    parameterNames = CompatUri.getQueryParameterNames(url);
                } else {
                    parameterNames = url.getQueryParameterNames();
                }
                String extractedFragment = url.getEncodedFragment();

                if (parameterNames.contains("error")) {
                    view.stopLoading();

                    // In case of an error, the `error` parameter contains an ASCII identifier, e.g.
                    // "temporarily_unavailable" and the `error_description` *may* contain a
                    // human-readable description of the error.
                    //
                    // For a list of the error identifiers, see
                    // http://tools.ietf.org/html/rfc6749#section-4.1.2.1

                    String error = url.getQueryParameter("error");
                    String errorDescription = url.getQueryParameter("error_description");

                    // If the user declines to authorise the app, there's no need to show an error
                    // message.
                    if (!error.equals("access_denied")) {
                        showErrorDialog(String.format("Error code: %s\n\n%s", error,
                                errorDescription));
                    }
                } else if (urlString.startsWith(redirectUrl)) {
                    // We won't need to keep loading anymore. This also prevents errors when using
                    // redirect URLs that don't have real protocols (like app://) that are just
                    // used for identification purposes in native apps.
                    view.stopLoading();

                    switch (flowType) {
                        case Implicit: {
                            if (!TextUtils.isEmpty(extractedFragment)) {
                                CreateIdTokenFromFragmentPartTask task = new CreateIdTokenFromFragmentPartTask();
                                task.execute(extractedFragment);

                            } else {
                                Log.e(TAG, String.format(
                                        "urlString '%1$s' doesn't contain fragment part; can't extract tokens",
                                        urlString));
                            }
                            break;
                        }
                        case Hybrid: {
                            if (!TextUtils.isEmpty(extractedFragment)) {
                                RequestIdTokenFromFragmentPartTask task = new RequestIdTokenFromFragmentPartTask();
                                task.execute(extractedFragment);

                            } else {
                                Log.e(TAG, String.format(
                                        "urlString '%1$s' doesn't contain fragment part; can't request tokens",
                                        urlString));
                            }
                            break;
                        }
                        case Code:
                        default: {
                            // The URL will contain a `code` parameter when the user has been authenticated
                            if (parameterNames.contains("code")) {
                                String authToken = url.getQueryParameter("code");

                                // Request the ID token
                                RequestIdTokenTask task = new RequestIdTokenTask();
                                task.execute(authToken);
                            } else {
                                Log.e(TAG, String.format(
                                        "urlString '%1$s' doesn't contain code param; can't extract authCode",
                                        urlString));
                            }
                            break;
                        }
                    }
                }
                // else : should be an intermediate url, load it and keep going
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                String cookies = CookieManager.getInstance().getCookie(url);
                Log.d(TAG, "All the cookies in a string:" + cookies);
            }
        });

        //OIDC options form container
        setupOIDCOptionsForm();

        if (needsOptionsForm) {
            webView.setVisibility(View.INVISIBLE);
            clientFormLayout.setVisibility(View.VISIBLE);

            Log.d(TAG, "Initiated activity for completing OIDC client options.");
        }
        else {
            webView.setVisibility(View.VISIBLE);
            clientFormLayout.setVisibility(View.INVISIBLE);

            // Fetch the OIDC client options from the bundle extras
            clientId = extras.getString(KEY_OPT_OIDC_CLIENT_ID);
            clientSecret = extras.getString(KEY_OPT_OIDC_CLIENT_SECRET);
            redirectUrl = extras.getString(KEY_OPT_OIDC_CLIENT_REURL);
            scopes = extras.getStringArray(KEY_OPT_OIDC_CLIENT_SCOPES);
            realm = extras.getString(KEY_OPT_OIDC_CLIENT_REALM);
            flowType = Config.Flows.valueOf(extras.getString(KEY_OPT_OIDC_CLIENT_FLOW_TYPE));

            // Generate the authentication URL using the oidc options set on the bundle
            String authUrl = OIDCUtils.newAuthenticationUrl(Config.authorizationServerUrl,
                    realm,
                    flowType,
                    clientId,
                    redirectUrl,
                    scopes);

            Log.d(TAG, String.format("Initiated activity for getting authorisation with URL '%s'.",
                    authUrl));

            webView.loadUrl(authUrl);
        }
    }

    private void setupOIDCOptionsForm() {
        clientFormLayout = findViewById(R.id.clientFormLayout);
        validateClientButton = (Button) findViewById(R.id.setOIDCClientButton);
        validateClientButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setOIDCClientInfo(v);
            }
        });
        flowTypeSpinner = (Spinner) findViewById(R.id.flowTypeSpinner);
        flowTypeSpinner.setAdapter(new FlowTypesAdapter(this, android.R.layout.simple_spinner_item, Config.Flows.values()));

        setupFormFloatingLabel();
    }

    private void setupFormFloatingLabel() {
        clientIdInputLayout = (TextInputLayout) findViewById(R.id.clientIdInputLayout);
        clientIdInputLayout.getEditText().addTextChangedListener(new OIDCOptionsTextWatcher(clientIdInputLayout));

        clientSecretInputLayout = (TextInputLayout) findViewById(R.id.clientSecretInputLayout);
        clientSecretInputLayout.getEditText().addTextChangedListener(new OIDCOptionsTextWatcher(clientSecretInputLayout));

        redirectUriInputLayout = (TextInputLayout) findViewById(R.id.redirectUriInputLayout);
        redirectUriInputLayout.getEditText().addTextChangedListener(new OIDCOptionsTextWatcher(redirectUriInputLayout));

        scopesInputLayout = (TextInputLayout) findViewById(R.id.scopesInputLayout);
        scopesInputLayout.getEditText().addTextChangedListener(new OIDCOptionsTextWatcher(scopesInputLayout));
    }

    public void setOIDCClientInfo(View view) {

        // Fetch the OIDC client options from the form
        EditText clientidEdit = (EditText) findViewById(R.id.clientIdEditText);
        EditText clientSecretEdit = (EditText) findViewById(R.id.clientSecretEditText);
        EditText redirectUriEdit = (EditText) findViewById(R.id.redirectUriEditText);
        EditText scopesEdit = (EditText) findViewById(R.id.scopesEditText);

        clientId = clientidEdit.getText().toString();
        clientSecret = clientSecretEdit.getText().toString();
        redirectUrl = redirectUriEdit.getText().toString();
        if (TextUtils.isEmpty(scopesEdit.getText().toString())) {
            scopes = null;
        }
        else {
            scopes = scopesEdit.getText().toString().split(" ");
        }
        flowType = (Config.Flows) flowTypeSpinner.getSelectedItem();

        if (isOIDCClientInfoOk(clientId, clientSecret, redirectUrl, scopes)) {

            // Generate a new authorisation URL
            String authUrl = OIDCUtils.newAuthenticationUrl(Config.authorizationServerUrl,
                    realm,
                    flowType,
                    clientId,
                    redirectUrl,
                    scopes);

            Log.d(TAG, String.format("Initiates WebView workflow with URL '%s'.", authUrl));

            clientFormLayout.setVisibility(View.INVISIBLE);
            webView.setVisibility(View.VISIBLE);
            webView.loadUrl(authUrl);
        }
    }

    protected class OIDCOptionsTextWatcher implements TextWatcher {
        TextInputLayout textInputLayout;

        public OIDCOptionsTextWatcher(TextInputLayout textInputLayout) {
            this.textInputLayout = textInputLayout;
        }

        @Override
        public void beforeTextChanged(CharSequence s, int start, int count, int after) {

        }

        @Override
        public void onTextChanged(CharSequence s, int start, int before, int count) {
            textInputLayout.setErrorEnabled(false);
        }

        @Override
        public void afterTextChanged(Editable s) {

        }
    }

    private boolean isOIDCClientInfoOk(String clientId, String secret, String redirectUrl, String[] scopes) {
        boolean isOk = true;
        if (TextUtils.isEmpty(clientId)){
            clientIdInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            clientIdInputLayout.setErrorEnabled(true);
            isOk = false;
        }
        if (TextUtils.isEmpty(secret)){
            clientSecretInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            clientSecretInputLayout.setErrorEnabled(true);
            isOk = false;
        }
        if (TextUtils.isEmpty(redirectUrl)){
            redirectUriInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            redirectUriInputLayout.setErrorEnabled(true);
            isOk = false;
        }
        if (scopes == null || scopes.length == 0){
            scopesInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            scopesInputLayout.setErrorEnabled(true);
            isOk = false;
        }

        return  isOk;
    }

    /**
     * Implicit flow
     */
    private class CreateIdTokenFromFragmentPartTask extends AsyncTask<String, Void, Boolean> {

        @Override
        protected Boolean doInBackground(String... args) {
            String fragmentPart = args[0];

            Uri tokenExtrationUrl = new Uri.Builder().encodedQuery(fragmentPart).build();
            String accessToken = tokenExtrationUrl.getQueryParameter("access_token");
            String idToken = tokenExtrationUrl.getQueryParameter("id_token");
            String tokenType = tokenExtrationUrl.getQueryParameter("token_type");
            String expiresInString = tokenExtrationUrl.getQueryParameter("expires_in");
            Long expiresIn = (!TextUtils.isEmpty(expiresInString)) ? Long.decode(expiresInString) : null;

            String scope = tokenExtrationUrl.getQueryParameter("scope");
            //TODO: Should check the state to to handle cross-site attacks
            //String state = tokenExtrationUrl.getQueryParameter("state");

            if (TextUtils.isEmpty(accessToken) || TextUtils.isEmpty(idToken) || TextUtils.isEmpty(tokenType) || expiresIn == null) {
                return false;
            }
            else {
                Log.i(TAG, "AuthToken : " + accessToken);

                IdTokenResponse response = new IdTokenResponse();
                response.setAccessToken(accessToken);
                response.setIdToken(idToken);
                response.setTokenType(tokenType);
                response.setExpiresInSeconds(expiresIn);
                response.setScope(scope);
                response.setFactory(new GsonFactory());

                if (isNewAccount) {
                    createAccount(response);
                } else {
                    AccountUtils.saveTokens(accountManager, account, response);
                }
            }

            return true;
        }

        @Override
        protected void onPostExecute(Boolean wasSuccess) {
            if (wasSuccess) {
                // The account manager still wants the following information back
                Intent intent = new Intent();

                intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, account.name);
                intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, account.type);

                setAccountAuthenticatorResult(intent.getExtras());
                setResult(RESULT_OK, intent);
                finish();
            } else {
                showErrorDialog("Could not get ID Token.");
            }
        }
    }

    /**
     * Hybrid flow
     */
    private class RequestIdTokenFromFragmentPartTask extends AsyncTask<String, Void, Boolean> {
        @Override
        protected Boolean doInBackground(String... args) {
            String fragmentPart = args[0];

            Uri tokenExtrationUrl = new Uri.Builder().encodedQuery(fragmentPart).build();
            String idToken = tokenExtrationUrl.getQueryParameter("id_token");
            String authCode = tokenExtrationUrl.getQueryParameter("code");

            //TODO: Should check the state to to handle cross-site attacks
            //String state = tokenExtrationUrl.getQueryParameter("state");

            if (TextUtils.isEmpty(idToken) || TextUtils.isEmpty(authCode)) {
                return false;
            }
            else {
                IdTokenResponse response;

                Log.i(TAG, "Requesting access_token with AuthCode : " + authCode);

                try {
                    response = OIDCUtils.requestTokens(Config.tokenServerUrl,
                            realm,
                            redirectUrl,
                            clientId,
                            clientSecret,
                            authCode);
                } catch (IOException e) {
                    Log.e(TAG, "Could not get response.");
                    e.printStackTrace();
                    return false;
                }

                if (isNewAccount) {
                    createAccount(response);
                } else {
                    AccountUtils.saveTokens(accountManager, account, response);
                }
            }

            return true;
        }

        @Override
        protected void onPostExecute(Boolean wasSuccess) {
            if (wasSuccess) {
                // The account manager still wants the following information back
                Intent intent = new Intent();

                intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, account.name);
                intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, account.type);

                setAccountAuthenticatorResult(intent.getExtras());
                setResult(RESULT_OK, intent);
                finish();
            } else {
                showErrorDialog("Could not get ID Token.");
            }
        }
    }

    /**
     * Requests the ID Token asynchronously.
     */
    private class RequestIdTokenTask extends AsyncTask<String, Void, Boolean> {
        @Override
        protected Boolean doInBackground(String... args) {
            String authToken = args[0];
            IdTokenResponse response;

            Log.d(TAG, "Requesting ID token.");

            try {
                response = OIDCUtils.requestTokens(Config.tokenServerUrl,
                        realm,
                        redirectUrl,
                        clientId,
                        clientSecret,
                        authToken);
            } catch (IOException e) {
                Log.e(TAG, "Could not get response.");
                e.printStackTrace();
                return false;
            }

            if (isNewAccount) {
                createAccount(response);
            } else {
                AccountUtils.saveTokens(accountManager, account, response);
            }

            return true;
        }

        @Override
        protected void onPostExecute(Boolean wasSuccess) {
            if (wasSuccess) {
                // The account manager still wants the following information back
                Intent intent = new Intent();

                intent.putExtra(AccountManager.KEY_ACCOUNT_NAME, account.name);
                intent.putExtra(AccountManager.KEY_ACCOUNT_TYPE, account.type);

                setAccountAuthenticatorResult(intent.getExtras());
                setResult(RESULT_OK, intent);
                finish();
            } else {
                showErrorDialog("Could not get ID Token.");
            }
        }
    }

    private void createAccount(IdTokenResponse response) {
        Log.d(TAG, "Creating account.");

        String accountType = getString(R.string.ACCOUNT_TYPE);

        // AccountManager expects that each account has a unique username. If a new account has the
        // same username as a previously created one, it will overwrite the older account.
        //
        // Unfortunately the OIDC spec cannot guarantee[1] that any user information is unique,
        // save for the user ID (i.e. the ID Token subject) which is hardly human-readable. This
        // makes choosing between multiple accounts difficult.
        //
        // We'll resort to naming each account `given_name (ID)`. This is a neat solution
        // if the user ID is short enough.
        //
        // [1]: http://openid.net/specs/openid-connect-basic-1_0.html#ClaimStability

        // Use the app name as a fallback if the other information isn't available for some reason.
        String accountName = getString(R.string.app_name);
        String accountId = null;

        try {
            accountId = response.parseIdToken().getPayload().getSubject();
        } catch (IOException e) {
            Log.e(TAG, "Could not get ID Token subject.");
            e.printStackTrace();
        }

        // Get the user information so we can grab the `given_name`
        Map userInfo = Collections.emptyMap();

        try {
//            userInfo = OIDCUtils.getUserInfo(Config.userInfoUrl, response.getIdToken());
            userInfo = OIDCUtils.getUserInfo(Config.userInfoUrl, realm, response.getAccessToken());
        } catch (IOException e) {
            Log.e(TAG, "Could not get UserInfo.");
            e.printStackTrace();
        }

        if (userInfo.containsKey("given_name")) {
            accountName = (String) userInfo.get("given_name");
        }

        account = new Account(String.format("%s (%s)", accountName, accountId), accountType);
        accountManager.addAccountExplicitly(account, null, null);

        // Store the tokens in the account
        AccountUtils.saveTokens(accountManager, account, response);

        Log.d(TAG, "Account created.");
    }

    /**
     * TODO: Improve error messages.
     */
    private void showErrorDialog(String message) {
        new AlertDialog.Builder(AuthenticatorActivity.this)
                .setTitle("Sorry, there was an error")
                .setMessage(message)
                .setCancelable(true)
                .setNeutralButton("Close", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        dialogInterface.dismiss();
                        finish();
                    }
                })
                .create()
                .show();
    }

    /**
     * Create an intent for showing the authorisation web page from an external app/service context.
     * This is usually used to request authorization when tokens expire.
     * @param context the Context where the intent is trigger from, like Activity, App, or Service
     * @param account the account that we need authorization for
     * @param options contains the OIDC client options (clientId, clientSecret, redirectUrl, scopes)
     * @return an intent to open AuthenticatorActivity
     */
    public static Intent createIntentForReAuthorization(Context context, Account account, Bundle options) {
        Intent intent = new Intent(context, AuthenticatorActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtras(options);
        intent.putExtra(AuthenticatorActivity.KEY_PRESENT_OPTS_FORM, false);
        intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_OBJECT, account);

        return intent;
    }

    private class FlowTypesAdapter extends ArrayAdapter<Config.Flows> {
        public FlowTypesAdapter(Context context, int resource, Config.Flows[] objects) {
            super(context, resource, objects);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.spinner_item_flowtype, parent, false);
            }

            Config.Flows item = getItem(position);
            TextView textView = (TextView) convertView.findViewById(android.R.id.text1);
            textView.setText(String.format(getString(R.string.OIDCFlowTypeOptionHint), item.name()));

            return convertView;
        }

        @Override
        public View getDropDownView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.spinner_item_flowtype, parent, false);
            }

            Config.Flows item = getItem(position);
            TextView textView = (TextView) convertView.findViewById(android.R.id.text1);
            textView.setText(item.name());

            return convertView;
        }
    }
}
