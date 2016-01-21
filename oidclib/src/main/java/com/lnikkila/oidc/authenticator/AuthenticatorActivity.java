package com.lnikkila.oidc.authenticator;

import android.accounts.Account;
import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.app.AlertDialog;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
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
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.json.gson.GsonFactory;
import com.lnikkila.oidc.OIDCAccountManager;
import com.lnikkila.oidc.OIDCUtils;
import com.lnikkila.oidc.R;
import com.lnikkila.oidc.minsdkcompat.CompatUri;
import com.lnikkila.oidc.security.UserNotAuthenticatedWrapperException;

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

    public static final int ASK_USER_ENCRYPT_PIN_REQUEST_CODE = 1;

    public static final String KEY_PRESENT_OPTS_FORM    = "com.lnikkila.oidc.KEY_PRESENT_OPTS_FORM";
    public static final String KEY_IS_NEW_ACCOUNT       = "com.lnikkila.oidc.KEY_IS_NEW_ACCOUNT";
    public static final String KEY_ACCOUNT_NAME         = "com.lnikkila.oidc.KEY_ACCOUNT_NAME";

    protected String authorizationEnpoint;
    protected String tokenEndpoint;
    protected String userInfoEndpoint;

    private OIDCAccountManager accountManager;
    private KeyguardManager keyguardManager;
    private Account account;
    private boolean isNewAccount;

    protected String clientId;
    protected String clientSecret;
    protected String redirectUrl;
    protected String[] scopes;
    protected OIDCUtils.Flows flowType;

    /*package*/ RelativeLayout parentLayout;
    /*package*/ WebView webView;
    /*package*/ View clientFormLayout;
    /*package*/ TextInputLayout clientIdInputLayout;
    /*package*/ TextInputLayout clientSecretInputLayout;
    /*package*/ TextInputLayout redirectUriInputLayout;
    /*package*/ TextInputLayout scopesInputLayout;
    /*package*/ Button validateClientButton;
    /*package*/ Spinner flowTypeSpinner;

    //region Activity Lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authentication);

        authorizationEnpoint = getString(R.string.op_authorizationEnpoint);
        tokenEndpoint = getString(R.string.op_tokenEndpoint);
        userInfoEndpoint = getString(R.string.op_userInfoEndpoint);

        accountManager = new OIDCAccountManager(this);
        keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);

        Bundle extras = getIntent().getExtras();

        // Are we supposed to create a new account or renew the authorisation of an old one?
        isNewAccount = extras.getBoolean(KEY_IS_NEW_ACCOUNT, false);

        // In case we're renewing authorisation, we also got an Account object that we're supposed
        // to work with.
        String accountName = extras.getString(KEY_ACCOUNT_NAME);
        if (accountName != null) {
            account = accountManager.getAccountByName(accountName);
        }

        // In case that the needed OIDC options are not set, present form to set them in order to create the authentication URL
        boolean needsOptionsForm = extras.getBoolean(KEY_PRESENT_OPTS_FORM, false);

        parentLayout = (RelativeLayout) findViewById(R.id.authenticatorActivityLayout);

        // Initialise the WebView
        // see  http://stackoverflow.com/a/8011027/665823 of why we doing this :
        webView = new WebView(this);
        parentLayout.addView(webView, new RelativeLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
        //instead of this :
        //webView = (WebView) findViewById(R.id.WebView);

        //TODO: Enable this if your authorisation page requires JavaScript
        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new AuthorizationWebViewClient());

        // Initialise the OIDC client definition form
        clientFormLayout = findViewById(R.id.clientFormLayout);

        if (needsOptionsForm) {
            //OIDC options form container
            setupOIDCOptionsForm();

            webView.setVisibility(View.GONE);
            clientFormLayout.setVisibility(View.VISIBLE);

            Log.d(TAG, "Initiated activity for completing OIDC client options.");
        }
        else {
            // Fetch the OIDC client options from the bundle extras
            clientId = this.getString(R.string.oidc_clientId);
            clientSecret = this.getString(R.string.oidc_clientSecret);
            redirectUrl = this.getString(R.string.oidc_redirectUrl).toLowerCase();
            scopes = this.getResources().getStringArray(R.array.oidc_scopes);
            flowType = OIDCUtils.Flows.valueOf(this.getString(R.string.oidc_flowType));

            //FIXME realm = extras.getString(KEY_OPT_OIDC_CLIENT_REALM);

            if (flowType == OIDCUtils.Flows.Password) {
                clientFormLayout.setVisibility(View.VISIBLE);
                webView.setVisibility(View.GONE);
                setupPasswordGrantForm();

                Log.d(TAG, "Initiated activity for password grant form.");
            }
            else {
                clientFormLayout.setVisibility(View.GONE);
                webView.setVisibility(View.VISIBLE);
                String authUrl = getAuthenticationUrl();
                webView.loadUrl(authUrl);
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.d(TAG, "KeyguardSecure is not used for pre M devices");
        } else {
            if (accountManager.isKeyPinRequired() && !keyguardManager.isKeyguardSecure()) {
                Toast.makeText(this,
                        "Secure lock screen hasn't set up. Go to 'Settings -> Security -> Screenlock' to set up a lock screen",
                        Toast.LENGTH_LONG).show();
            }
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        //Handles possible webView leak : http://stackoverflow.com/a/8011027/665823
        parentLayout.removeAllViews();
        webView.destroy();
    }

    //endregion

    //region Requests to the Identity Provider

    protected String getAuthenticationUrl() {
        // Generate the authentication URL using the oidc options set on the bundle
        String authUrl = OIDCUtils.newAuthenticationUrl(authorizationEnpoint, flowType, clientId,
                redirectUrl, scopes);

        Log.d(TAG, String.format("Initiated activity for getting authorisation with URL '%s'.", authUrl));
        return authUrl;
    }

    @Nullable
    protected IdTokenResponse requestAccessTokenWithAuthCode(String authCode) {
        IdTokenResponse response = null;

        try {
            response = (IdTokenResponse) OIDCUtils.requestTokensWithCodeGrant(
                    tokenEndpoint,
                    redirectUrl,
                    clientId,
                    clientSecret,
                    authCode,
                    true);
        } catch (IOException e) {
            Log.e(TAG, "Could not get response.", e);
        }
        return response;
    }

    @Nullable
    protected TokenResponse requestAccessTokenWithUserNamePassword(String userName, String userPwd) {
        TokenResponse response = null;
        try {
            response = OIDCUtils.requestTokensWithPasswordGrant(
                    tokenEndpoint,
                    clientId,
                    clientSecret,
                    scopes,
                    userName,
                    userPwd);
        } catch (IOException e) {
            Log.e(TAG, "Could not get response.", e);
        }

        return response;
    }

    //endregion

    //region Layout setups

    private void setupOIDCOptionsForm() {
        validateClientButton = (Button) findViewById(R.id.setOIDCClientButton);
        validateClientButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                setOIDCClientInfo(v);
            }
        });
        flowTypeSpinner = (Spinner) findViewById(R.id.flowTypeSpinner);
        flowTypeSpinner.setAdapter(new FlowTypesAdapter(this, android.R.layout.simple_spinner_item, OIDCUtils.Flows.values()));

        setupFormFloatingLabel();
    }

    private class FlowTypesAdapter extends ArrayAdapter<OIDCUtils.Flows> {
        public FlowTypesAdapter(Context context, int resource, OIDCUtils.Flows[] objects) {
            super(context, resource, objects);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.spinner_item_flowtype, parent, false);
            }

            OIDCUtils.Flows item = getItem(position);
            TextView textView = (TextView) convertView.findViewById(android.R.id.text1);
            textView.setText(String.format(getString(R.string.OIDCFlowTypeOptionHint), item.name()));

            return convertView;
        }

        @Override
        public View getDropDownView(int position, View convertView, ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.spinner_item_flowtype, parent, false);
            }

            OIDCUtils.Flows item = getItem(position);
            TextView textView = (TextView) convertView.findViewById(android.R.id.text1);
            textView.setText(item.name());

            return convertView;
        }
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
        redirectUrl = redirectUriEdit.getText().toString().toLowerCase();
        if (TextUtils.isEmpty(scopesEdit.getText().toString())) {
            scopes = null;
        }
        else {
            scopes = scopesEdit.getText().toString().split(" ");
        }
        flowType = (OIDCUtils.Flows) flowTypeSpinner.getSelectedItem();

        if (isOIDCClientInfoOk(clientId, clientSecret, redirectUrl, scopes)) {

            // Generate a new authorisation URL
            String authUrl = getAuthenticationUrl();

            Log.d(TAG, String.format("Initiates WebView workflow with URL '%s'.", authUrl));

            clientFormLayout.setVisibility(View.INVISIBLE);
            webView.setVisibility(View.VISIBLE);
            webView.loadUrl(authUrl);
        }
    }

    protected static class OIDCOptionsTextWatcher implements TextWatcher {
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

    private void setupPasswordGrantForm() {
        setupFormFloatingLabel();
        flowTypeSpinner = (Spinner) findViewById(R.id.flowTypeSpinner);

        redirectUriInputLayout.setVisibility(View.GONE);
        scopesInputLayout.setVisibility(View.GONE);
        flowTypeSpinner.setVisibility(View.GONE);

        clientIdInputLayout.setHint(getString(R.string.OIDCUserNameOptionHint));
        clientSecretInputLayout.setHint(getString(R.string.OIDCUserPwdOptionHint));

        validateClientButton = (Button) findViewById(R.id.setOIDCClientButton);
        validateClientButton.setText(R.string.OIDCLoginnHint);
        validateClientButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText userNameEdit = (EditText) findViewById(R.id.clientIdEditText);
                EditText userPwdEdit = (EditText) findViewById(R.id.clientSecretEditText);

                String userName = userNameEdit.getText().toString();
                String userPwd = userPwdEdit.getText().toString();

                if (isPasswordGrantInfoOk(userName, userPwd)) {
                    PasswordFlowTask task = new PasswordFlowTask();
                    task.execute(userName, userPwd);
                }
            }
        });


    }

    private boolean isPasswordGrantInfoOk(String userName, String userPwd) {
        boolean isOk = true;
        if (TextUtils.isEmpty(userName)){
            clientIdInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            clientIdInputLayout.setErrorEnabled(true);
            isOk = false;
        }
        if (TextUtils.isEmpty(userPwd)){
            clientSecretInputLayout.setError(getString(R.string.OIDCOptionsMandatoryError));
            clientSecretInputLayout.setErrorEnabled(true);
            isOk = false;
        }
        return  isOk;
    }

    //endregion

    //region Flow handling

    /**
     * Handles the result embedded in the redirect URI.
     *
     * @param redirectUriString Received redirect URI with query parameters.
     */
    private void finishAuthorization(String redirectUriString) {
        Uri redirectUri = Uri.parse(redirectUriString);

        Set<String> parameterNames;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
            parameterNames = CompatUri.getQueryParameterNames(redirectUri);
        } else {
            parameterNames = redirectUri.getQueryParameterNames();
        }

        String extractedFragment = redirectUri.getEncodedFragment();

        switch (flowType) {
            case Implicit: {
                if (!TextUtils.isEmpty(extractedFragment)) {
                    ImplicitFlowTask task = new ImplicitFlowTask();
                    task.execute(extractedFragment);

                } else {
                    Log.e(TAG, String.format(
                            "redirectUriString '%1$s' doesn't contain fragment part; can't extract tokens",
                            redirectUriString));
                }
                break;
            }
            case Hybrid: {
                if (!TextUtils.isEmpty(extractedFragment)) {
                    HybridFlowTask task = new HybridFlowTask();
                    task.execute(extractedFragment);

                } else {
                    Log.e(TAG, String.format(
                            "redirectUriString '%1$s' doesn't contain fragment part; can't request tokens",
                            redirectUriString));
                }
                break;
            }
            case Code:
            default: {
                // The URL will contain a `code` parameter when the user has been authenticated
                if (parameterNames.contains("code")) {
                    String authToken = redirectUri.getQueryParameter("code");

                    // Request the ID token
                    CodeFlowTask task = new CodeFlowTask();
                    task.execute(authToken);
                } else {
                    Log.e(TAG, String.format(
                            "redirectUriString '%1$s' doesn't contain code param; can't extract authCode",
                            redirectUriString));
                }
                break;
            }
        }
    }

    /**
     * Tries to handle errors on the given URI. Authorization errors are handled when the URI
     * contains a "error" parameter.
     *
     * @param uri URI to handle.
     * @return Whether the URI had an error to handle.
     */
    private boolean handleAuthorizationErrors(String uri){
        Uri parsedUri = Uri.parse(uri);

        Set<String> parameterNames;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
            parameterNames = CompatUri.getQueryParameterNames(parsedUri);
        } else {
            parameterNames = parsedUri.getQueryParameterNames();
        }

        // We need to check if the error is not in the fragment (for Implicit/Hybrid Flow)
        if (parameterNames.isEmpty()) {
            String extractedFragment = parsedUri.getEncodedFragment();
            if (!TextUtils.isEmpty(extractedFragment)) {
                parsedUri = new Uri.Builder().encodedQuery(extractedFragment).build();
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
                    parameterNames = CompatUri.getQueryParameterNames(parsedUri);
                }
                else {
                    parameterNames = parsedUri.getQueryParameterNames();
                }
            }
        }


        if (parameterNames.contains("error")) {
            // In case of an error, the `error` parameter contains an ASCII identifier, e.g.
            // "temporarily_unavailable" and the `error_description` *may* contain a
            // human-readable description of the error.
            //
            // For a list of the error identifiers, see
            // http://tools.ietf.org/html/rfc6749#section-4.1.2.1
            String error = parsedUri.getQueryParameter("error");
            String errorDescription = parsedUri.getQueryParameter("error_description");

            // If the user declines to authorise the app, there's no need to show an error message.
            if (error.equals("access_denied")) {
                Log.i(TAG, String.format("User declines to authorise the app : %s", errorDescription));
            }
            else {
                showErrorDialog("Error code: %s\n\n%s", error, errorDescription);
            }

            return true;
        }
        else {
            return false;
        }
    }

    /**
     * Tries to handle the given URI as the redirect URI.
     *
     * @param uri URI to handle.
     * @return Whether the URI was handled.
     */
    private boolean handleUri(String uri) {
        if (handleAuthorizationErrors(uri)) {
            return true;
        }
        else if (uri.startsWith(redirectUrl)) {
            finishAuthorization(uri);
            return true;
        }

        return false;
    }

    private class AuthorizationWebViewClient extends WebViewClient {

        /**
         * Forces the WebView to not load the URL if it can be handled.
         */
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return handleUri(url) || super.shouldOverrideUrlLoading(view, url);
        }

        @Override
        public void onReceivedError(WebView view, int errorCode, String description, String url) {
            showErrorDialog("Network error: got %s for %s.", description, url);
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            String cookies = CookieManager.getInstance().getCookie(url);
            Log.d(TAG, String.format("Cookies for url %1$s : %2$s", url, cookies));
        }
    }

    /**
     * Abstract task for authorization flows handling.
     */
    private abstract class AuthorizationFlowTask extends AsyncTask<String, Void, Boolean> {
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
     * Handles Implicit flow by creating an {@link IdTokenResponse} from a Uri fragment asynchronously.
     * <br/>
     * An Uri string containing a Uri fragment is passed as first parameter of the
     * {@link AsyncTask#execute(Object[])} method, i.e :
     * <br/>
     * <i>
     * http://domain/redirect.html#scope=offline_access%20openid%20profile&state=xyz&code=xxx&id_token=yyyy
     * </i>
     */
    private class ImplicitFlowTask extends AuthorizationFlowTask {

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
                    saveTokens(response);
                }
            }

            return true;
        }
    }

    /**
     * Handles Hybrid flow by extracting asynchronously the authorization code from a Uri fragment
     * then exchanging it for an {@link IdTokenResponse} by making a request to the
     * {@link #tokenEndpoint}.
     * <br/>
     * An Uri string containing a Uri fragment is passed as first parameter of the
     * {@link AsyncTask#execute(Object[])} method, i.e :
     * <br/>
     * <i>
     * http://domain/redirect.html#scope=offline_access%20openid%20profile&state=xyz&code=xxx&id_token=yyyy
     * </i>
     */
    private class HybridFlowTask extends AuthorizationFlowTask {
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
                Log.i(TAG, "Requesting access_token with AuthCode : " + authCode);

                IdTokenResponse response = requestAccessTokenWithAuthCode(authCode);

                if (response == null) {
                    return false;
                }
                else {
                    if (isNewAccount) {
                        createAccount(response);
                    } else {
                        saveTokens(response);
                    }

                    return true;
                }
            }
        }
    }

    /**
     * Handles Code flow by requesting asynchronously a {@link IdTokenResponse} to the
     * {@link #tokenEndpoint} using an authorization code.
     * <br/>
     * The authorization code is passed as first parameter of the
     * {@link AsyncTask#execute(Object[])} method.
     * <br/>
     */
    private class CodeFlowTask extends AuthorizationFlowTask {
        @Override
        protected Boolean doInBackground(String... args) {
            String authCode = args[0];

            Log.i(TAG, "Requesting access_token with AuthCode : " + authCode);

            IdTokenResponse response = requestAccessTokenWithAuthCode(authCode);

            if (response == null) {
                return false;
            }
            else {
                if (isNewAccount) {
                    createAccount(response);
                } else {
                    saveTokens(response);
                }

                return true;
            }
        }
    }

    private class PasswordFlowTask extends AuthorizationFlowTask {
        @Override
        protected Boolean doInBackground(String... args) {
            String userName = args[0];
            String userPwd = args[1];

            Log.d(TAG, "Requesting access_token with username : " + userName);

            TokenResponse response = requestAccessTokenWithUserNamePassword(userName, userPwd);

            if (response == null) {
                return false;
            }
            else {
                if (isNewAccount) {
                    createAccount(response);
                } else {
                    saveTokens(response);
                }

                return true;
            }
        }
    }

    //endregion

    //region Account Management
    private void createAccount(IdTokenResponse response) {
        Log.d(TAG, "Creating account.");

        String accountType = getString(R.string.account_authenticator_type);

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
            userInfo = OIDCUtils.getUserInfo(userInfoEndpoint, response.getAccessToken());
        } catch (IOException e) {
            Log.e(TAG, "Could not get UserInfo.");
            e.printStackTrace();
        }

        if (userInfo.containsKey("given_name")) {
            accountName = (String) userInfo.get("given_name");
        }

        account = new Account(String.format("%s (%s)", accountName, accountId), accountType);
        accountManager.getAccountManager().addAccountExplicitly(account, null, null);

        // Store the tokens in the account
        saveTokens(response);

        Log.d(TAG, "Account created.");
    }

    private void createAccount(TokenResponse response) {
        Log.d(TAG, "Creating account.");

        String accountType = getString(R.string.account_authenticator_type);
        String accountName = getString(R.string.app_name);

        account = new Account(accountName, accountType);
        accountManager.getAccountManager().addAccountExplicitly(account, null, null);

        Log.d(TAG, String.format("Saved tokens : (AT %1$s) (RT %2$s)", response.getAccessToken(), response.getRefreshToken()));

        // Store the tokens in the account
        saveTokens(response);

        Log.d(TAG, "Account created.");
    }

    //endregion


    private void saveTokens(TokenResponse response) {
        try {
            accountManager.saveTokens(account, response);
        } catch (UserNotAuthenticatedWrapperException e) {
            showAuthenticationScreen(ASK_USER_ENCRYPT_PIN_REQUEST_CODE);
        }
    }

    private void saveTokens(IdTokenResponse response) {
        try {
            accountManager.saveTokens(account, response);
        } catch (UserNotAuthenticatedWrapperException e) {
            showAuthenticationScreen(ASK_USER_ENCRYPT_PIN_REQUEST_CODE);
        }
    }

    /**
     * TODO: Improve error messages.
     *
     * @param message Error message that can contain formatting placeholders.
     * @param args    Formatting arguments for the message, or null.
     */
    private void showErrorDialog(String message, String... args) {
        if (args != null) {
            message = String.format(message, args);
        }

        new AlertDialog.Builder(this)
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

    private void showAuthenticationScreen(int requestCode) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.e(TAG, "This should never happend for pre M devices");
        } else {
            Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
            if (intent != null) {
                startActivityForResult(intent, requestCode);
            }
        }
    }

    /**
     * Create an intent for showing the authorisation web page from an external app/service context.
     * This is usually used to request authorization when tokens expire.
     * @param context the Context where the intent is trigger from, like Activity, App, or Service
     * @param accountName the account name that we need authorization for
     * @return an intent to open AuthenticatorActivity
     */
    public static Intent createIntentForReAuthorization(Context context, String accountName) {
        Intent intent = new Intent(context, AuthenticatorActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        intent.putExtra(AuthenticatorActivity.KEY_PRESENT_OPTS_FORM, false);
        intent.putExtra(AuthenticatorActivity.KEY_ACCOUNT_NAME, accountName);
        return intent;
    }
}
