package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ProgressBar;

import com.lnikkila.oidc.OIDCAccountManager;
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
public class HomeActivity extends Activity  {

    private static final String TAG = HomeActivity.class.getSimpleName();

    //TODO: set your protected resource url
    private static final String protectedResUrl = "https://www.example.com/res/my_res";

    protected String userInfoEndpoint;

    private Button loginButton;
    private Button requestButton;

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
        } else {
            requestButton.setVisibility(View.INVISIBLE);
            requestButton.setText(R.string.requestButton);
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

    public void doRequest(View view) {
        new ProtectedResTask().execute(availableAccounts[selectedAccountIndex]);
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
         * Makes the API request. We could use the OIDCUtils.getUserInfo() method, but we'll do it
         * like this to illustrate making generic API requests after we've logged in.
         */
        @Override
        protected Map doInBackground(Account... args) {
            Account account = args[0];

            try {
                return APIUtility.getJson(accountManager, userInfoEndpoint, account, null);
            } catch (AuthenticatorException | OperationCanceledException |IOException e) {
                e.printStackTrace(); //FIXME:
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
                Log.w(TAG, "We couldn't fetch userinfo from server");
            } else {
                loginButton.setText("Logged in as " + result.get("given_name"));
                Log.i(TAG, "We manage to login user to server");
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

    //endregion
}
