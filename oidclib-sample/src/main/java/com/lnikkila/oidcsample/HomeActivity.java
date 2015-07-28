package com.lnikkila.oidcsample;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ProgressBar;

import com.lnikkila.oidc.authenticator.Authenticator;

import java.io.IOException;
import java.util.Map;

/**
 * Initiates the login procedures and contains all UI stuff related to the main activity.
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
public class HomeActivity extends Activity implements TokensExpiredDialogListener {

    //TODO: set your protected resource url
    private static final String protectedResUrl = "https://www.example.com/res/my_res";

    private Button loginButton;
    private Button requestButton;

    private ProgressBar progressBar;
    private AccountManager accountManager;
    private Account availableAccounts[];

    private int selectedAccountIndex;
    private TokensExpiredCallBack accountCallBack;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_home);

        loginButton = (Button) findViewById(R.id.loginButton);
        requestButton = (Button) findViewById(R.id.requestButton);
        progressBar = (ProgressBar) findViewById(R.id.progressBar);
        progressBar.setVisibility(View.INVISIBLE);

        accountManager = AccountManager.get(this);
        accountCallBack = new TokensExpiredCallBack(this, this);
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

    protected void refreshAvailableAccounts() {
        // Grab all our accounts
        String accountType = getString(R.string.ACCOUNT_TYPE);
        availableAccounts = accountManager.getAccountsByType(accountType);
    }

    //region Buttons ClickListeners

    /**
     * Called when the user taps the big yellow button.
     */
    public void doLogin(final View view) {

        requestButton.setText(R.string.requestButton);

        String accountType = getString(R.string.ACCOUNT_TYPE);
        Bundle options = Config.getOIDCClientOptions();

        switch (availableAccounts.length) {
            // No account has been created, let's create one now
            case 0:
                accountManager.addAccount(accountType, Authenticator.TOKEN_TYPE_ID, null, options,
                        this, new AccountManagerCallback<Bundle>() {
                            @Override
                            public void run(AccountManagerFuture<Bundle> futureManager) {
                                // Unless the account creation was cancelled, try logging in again
                                // after the account has been created.
                                if (!futureManager.isCancelled()) {
                                    refreshAvailableAccounts();

                                    //NOTE: this is absoluptly needed for pre-ICS devices
                                    if(Build.VERSION.SDK_INT < Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
                                        Account account = availableAccounts[0];
                                        Config.setOIDCClientOptions(accountManager, account);
                                    }

                                    doLogin(view);
                                }
                            }
                        }, null);
                break;

            // There's just one account, let's use that
            case 1:
                new ApiTask().execute(availableAccounts[0]);
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
                                        new ApiTask().execute(availableAccounts[selectedAccountIndex]);
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

    //region TokensExpiredDialogListener

    @Override
    public void onRenewTokens(Intent renewIntent) {
        if (renewIntent != null) {
            renewIntent.setFlags(0);
            this.startActivity(renewIntent);
        }
    }

    @Override
    public void onDoNotRevewTokens() {

    }

    //endregion

    //region Background tasks

    private class ApiTask extends AsyncTask<Account, Void, Map> {

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
            Bundle options = Config.getOIDCClientOptions();

            try {
                return APIUtility.getJson(HomeActivity.this, com.lnikkila.oidc.Config.userInfoUrl, account, options, accountCallBack);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
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
            Bundle options = Config.getOIDCClientOptions();

            try {
                return APIUtility.getJson(HomeActivity.this, protectedResUrl, account, options, accountCallBack);
            } catch (IOException e) {
                e.printStackTrace();
                return null;
            }
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
