package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.Toast;

import com.lnikkila.oidc.OIDCAccountManager;
import com.lnikkila.oidc.authenticator.OIDCClientConfigurationActivity;
import com.lnikkila.oidc.security.UserNotAuthenticatedWrapperException;

import java.io.IOException;
import java.util.Map;

/**
 * Initiates the login procedures and contains all UI stuff related to the main activity.
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
@SuppressLint("SetTextI18n")
public class HomeActivity extends AppCompatActivity {

    private static final String TAG = HomeActivity.class.getSimpleName();
    private static final int RENEW_REFRESH_TOKEN = 2016;

    //TODO: set your protected resource url
    private static final String protectedResUrl = "https://www.example.com/res/my_res";

    protected String userInfoEndpoint;

    private Button loginButton;
    private Button requestButton;
    private Button logoutButton;

    private ProgressBar progressBar;
    private OIDCAccountManager accountManager;
    private Account availableAccounts[];

    private int selectedAccountIndex;

    //region Activity Lifecycle

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home);

        userInfoEndpoint = getString(R.string.op_userInfoEndpoint);

        loginButton = (Button) findViewById(R.id.loginButton);
        requestButton = (Button) findViewById(R.id.requestButton);
        logoutButton = (Button) findViewById(R.id.logoutButton);
        progressBar = (ProgressBar) findViewById(R.id.progressBar);
        progressBar.setVisibility(View.INVISIBLE);

        accountManager = new OIDCAccountManager(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshAvailableAccounts();


        if (availableAccounts.length > 0) {
            requestButton.setVisibility(View.VISIBLE);
            logoutButton.setVisibility(View.VISIBLE);
        } else {
            requestButton.setVisibility(View.INVISIBLE);
            requestButton.setText(R.string.requestButton);
            logoutButton.setVisibility(View.INVISIBLE);
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            if (requestCode == RENEW_REFRESH_TOKEN) {
                new LoginTask().execute(availableAccounts[selectedAccountIndex]);
            }
        }
    }

    //endregion

    //region Account Utilities

    protected void refreshAvailableAccounts() {
        // Grab all our accounts
        availableAccounts = accountManager.getAccounts();
    }

    //endregion

    //region Buttons ClickListeners

    /**
     * Called when the user taps the big yellow button.
     */
    public void doLogin(final View view) {

        requestButton.setText(R.string.requestButton);
        switch (availableAccounts.length) {
            // No account has been created, let's create one now
            case 0:
                accountManager.createAccount(this, new AccountManagerCallback<Bundle>() {
                    @Override
                    public void run(AccountManagerFuture<Bundle> futureManager) {
                        // Unless the account creation was cancelled, try logging in again
                        // after the account has been created.
                        if (!futureManager.isCancelled()) {
                            refreshAvailableAccounts();

                            // if we have an user endpoint we try to get userinfo with the receive token
                            if (!TextUtils.isEmpty(userInfoEndpoint)) {
                                new LoginTask().execute(availableAccounts[0]);
                            }
                        }
                    }
                });
                break;

            // There's just one account, let's use that
            case 1:
                // if we have an user endpoint we try to get userinfo with the receive token
                if (!TextUtils.isEmpty(userInfoEndpoint)) {
                    new LoginTask().execute(availableAccounts[0]);
                }
                break;

            // Multiple accounts, let the user pick one
            default:
                String name[] = new String[availableAccounts.length];

                for (int i = 0; i < availableAccounts.length; i++) {
                    name[i] = availableAccounts[i].name;
                }

                new AlertDialog.Builder(this)
                        .setTitle("Choose an account")
                        .setAdapter(new ArrayAdapter<>(this,
                                        android.R.layout.simple_list_item_1, name),
                                new DialogInterface.OnClickListener() {
                                    @Override
                                    public void onClick(DialogInterface dialog, int selectedAccount) {
                                        selectedAccountIndex = selectedAccount;

                                        // if we have an user endpoint we try to get userinfo with the receive token
                                        if (!TextUtils.isEmpty(userInfoEndpoint)) {
                                            new LoginTask().execute(availableAccounts[selectedAccountIndex]);
                                        }
                                    }
                                })
                        .create()
                        .show();
        }
    }

    public void doConfEdit(View view) {
        // Never use this on a release. The OpenId Connect client configuration should be stored in
        // a "secure" way (not on user preferences), if possible obfuscated, and not be allow to be edited.
        // Use it on dev or to test your OpenId Provider only.
        Intent intent = new Intent(this, OIDCClientConfigurationActivity.class);
        startActivity(intent);
    }

    public void doRequest(View view) {
        new ProtectedResTask().execute(availableAccounts[selectedAccountIndex]);
    }

    public void doLogout(View view) {
        new LogoutTask(false).execute(availableAccounts[selectedAccountIndex]);
    }

    //endregion

    //region Background tasks

    private class LoginTask extends AsyncTask<Account, Void, Map> {

        @Override
        protected void onPreExecute() {
            loginButton.setText("");
            progressBar.setVisibility(View.VISIBLE);
        }

        /**
         * Makes the API request. We could use the OIDCRequestManager.getUserInfo() method, but we'll do it
         * like this to illustrate making generic API requests after we've logged in.
         */
        @Override
        protected Map doInBackground(Account... args) {
            Account account = args[0];

            try {
                return APIUtility.getJson(accountManager, userInfoEndpoint, account, null);
            } catch (IOException e) {
                Log.w(TAG, "We couldn't fetch userinfo from server", e);
                handleTokenExpireException(account, e);
            } catch (AuthenticatorException | OperationCanceledException e) {
                Log.w(TAG, "Coudln't get access token from accountmanager", e);
            } catch (UserNotAuthenticatedWrapperException e) {
                //FIXME: we gotta handle this somehow
            }
            return null;
        }

        /**
         * Processes the API's response.
         */
        @Override
        protected void onPostExecute(Map result) {
            progressBar.setVisibility(View.INVISIBLE);

            if (result == null) {
                loginButton.setText("Couldn't get user info");
            } else {
                loginButton.setText("Logged in as " + result.get("given_name"));
                Log.i(TAG, "We manage to login user to server");
            }
        }

        private void handleTokenExpireException(Account account, IOException e){
            if (e.getMessage().contains("Access Token not valid")) {
                accountManager.invalidateAllAccountTokens(account);
                Log.i(TAG, "User should authenticate one more");
                launchExpiredTokensIntent(account);
            }
        }

        private void launchExpiredTokensIntent(Account account) {
            // See https://github.com/kalemontes/OIDCAndroidLib/issues/4
            try {
                accountManager.getAccessToken(account, new AccountManagerCallback<Bundle>() {
                    @Override
                    public void run(AccountManagerFuture<Bundle> future) {
                        try {
                            Bundle bundle = future.getResult();
                            Intent launch = (Intent) bundle.get(AccountManager.KEY_INTENT);
                            if (launch != null) {
                                launch.setFlags(0);
                                HomeActivity.this.startActivityForResult(launch, RENEW_REFRESH_TOKEN);
                            }
                        } catch (OperationCanceledException | IOException | AuthenticatorException e) {
                            Log.e(TAG, "Coudn't extract AuthenticationActivity lauch intent", e);
                        }
                    }
                });
            } catch (OperationCanceledException | IOException | AuthenticatorException e) {
                Log.e(TAG, "Couldn't renew tokens", e);
            } catch (UserNotAuthenticatedWrapperException e) {
                //FIXME: we gotta handle this somehow
            }
        }
    }

    private class ProtectedResTask extends AsyncTask<Account, Void, Map> {

        @Override
        protected void onPreExecute() {
            requestButton.setText("");
            progressBar.setVisibility(View.VISIBLE);
        }

        /**
         * Makes the API request to an SP.
         */
        @Override
        protected Map doInBackground(Account... args) {
            Account account = args[0];

            try {
                return APIUtility.getJson(accountManager, protectedResUrl, account, null);
            } catch (AuthenticatorException | OperationCanceledException |IOException e) {
                e.printStackTrace();
            } catch (UserNotAuthenticatedWrapperException e) {
                //FIXME: we gotta handle this somehow
            }
            return null;
        }

        /**
         * Processes the API's response.
         */
        @Override
        protected void onPostExecute(Map result) {
            progressBar.setVisibility(View.INVISIBLE);

            if (result == null) {
                requestButton.setText("Couldn't get request result");
            } else {
                requestButton.setText(result.toString());
            }
        }
    }

    private class LogoutTask extends AsyncTask<Account, Void, Boolean> {

        private boolean requestServerLogout;

        public LogoutTask(boolean requestServerLogout){
            this.requestServerLogout = requestServerLogout;
        }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
        }

        @Override
        protected Boolean doInBackground(Account... args) {
            Account account = args[0];
            return !requestServerLogout || requestServerLogout(account);
        }

        /**
         * Processes the API's response.
         */
        @Override
        protected void onPostExecute(Boolean result) {
            progressBar.setVisibility(View.INVISIBLE);

            if (result) {
                boolean removed = accountManager.removeAccount(availableAccounts[0]);
                if (removed) {
                    loginButton.setText(R.string.loginButtonText);
                    requestButton.setVisibility(View.INVISIBLE);
                    logoutButton.setVisibility(View.INVISIBLE);
                    refreshAvailableAccounts();

                    Toast.makeText(HomeActivity.this,
                            "Session closed",
                            Toast.LENGTH_SHORT).show();
                }
                else {
                    //TODO: show error message "Couldn't remove account"
                }
            } else {
                //TODO: show error message "Couldn't logout"
            }
        }

        private boolean requestServerLogout(Account account) {
            //TODO: make a request to the OP's revoke endpoint to invalidate the current tokens
            //See https://github.com/kalemontes/OIDCAndroidLib/issues/5 discution
            return false;
        }
    }

    //endregion
}
