package com.lnikkila.oidc;

import android.support.annotation.NonNull;
import android.text.TextUtils;
import android.util.Log;

import com.github.kevinsawicki.http.HttpRequest;
import com.google.api.client.auth.oauth2.AuthorizationCodeRequestUrl;
import com.google.api.client.auth.oauth2.AuthorizationCodeTokenRequest;
import com.google.api.client.auth.oauth2.AuthorizationRequestUrl;
import com.google.api.client.auth.oauth2.PasswordTokenRequest;
import com.google.api.client.auth.oauth2.RefreshTokenRequest;
import com.google.api.client.auth.oauth2.TokenResponse;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.android.http.AndroidHttp;
import com.google.api.client.http.BasicAuthentication;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.json.gson.GsonFactory;
import com.google.gson.Gson;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A layer of syntactic sugar around the google-oauth-java-client library to simplify using OpenID
 * Access on Android.
 *
 * Currently this helper class is fairly limited. It's suitable for our use case and pretty much
 * nothing else. Pull requests are appreciated!
 *
 * @author Leo Nikkilä
 * @author Camilo Montes
 */
public class OIDCUtils {

    /**
     * Supported OIDC Flows
     */
    public enum Flows
    {
        Code,  				//http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
        Implicit,           //http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
        Hybrid,             //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        Password
    }

    public static boolean isSupportedFlow(String value) {

        for (Flows c : Flows.values()) {
            if (c.name().equals(value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Generates an Authentication Request URL to the Authorization Endpoint to start an Implicit Flow.
     * When using the Implicit Flow, all tokens are returned from the Authorization Endpoint; the
     * Token Endpoint is not used so it allows to get all tokens on one trip. The downside is that
     * it doesn't support refresh tokens.
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth">Implicit Flow</a>
     */
    public static String implicitFlowAuthenticationUrl(String authorizationServerUrl, String clientId,
                                                       String redirectUrl, String[] scopes, String state,
                                                       Map<String, String> extras) {

        //TODO: see what the following statement implies :
        // "While OAuth 2.0 also defines the token Response Type value for the Implicit Flow,
        // OpenID Connect does not use this Response Type, since no ID Token would be returned"
        // from http://openid.net/specs/openid-connect-core-1_0.html#Authentication
        String[] responsesTypes = {"id_token", "token"};
        List<String> scopesList = Arrays.asList(scopes);
        List<String> responsesList = Arrays.asList(responsesTypes);

        //REQUIRED  OIDC request params
        AuthorizationRequestUrl request = new AuthorizationRequestUrl(authorizationServerUrl, clientId,
                responsesList)
                .setRedirectUri(redirectUrl)
                .setScopes(scopesList)
                .setState(state)
                .set("nonce", ""); //TODO: nonce is mandatory we should try to generate one

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        //OPTIONAL OIDC request params
        if (scopesList.contains("offline_access")) {
            // If the list of scopes includes the special `offline_access` scope that enables issuing
            // of Refresh Tokens, we need to ask for consent by including this parameter.
            request.set("prompt", "consent");
        } else {
            // Tell the server to ask for login details again. This ensures that in case of multiple
            // accounts, the user won't accidentally authorise the wrong one.
            request.set("prompt", "login");
        }

        // An optional request parameter that asks the server to provide a touch-enabled interface.
        // Who knows, maybe the server is nice enough to make some changes.
        request.set("display", "touch");

        return request.build();
    }

    /**
     * Generates an Authentication Request URL to the Authorization Endpoint to start an Hybrid Flow.
     * When using the Hybrid Flow, some tokens are returned from the Authorization Endpoint and
     * others are returned from the Token Endpoint.
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth">Hybrid Flow</a>
     */
    public static String hybridFlowAuthenticationUrl(String authorizationServerUrl, String clientId,
                                                     String redirectUrl, String[] scopes, String state,
                                                     Map<String, String> extras) {

        // The response type "code" is the only mandatory response type on hybrid flow, it must be
        // coupled with other response types to form one of the following values : "code id_token",
        // "code token", or "code id_token token".
        // For our needs "token" is not defined here because we want an access_token that has made
        // a client authentication. That access_token will be retrieve later using the TokenEndpoint
        // (see #requestTokensWithCodeGrant).
        String[] responsesTypes = {"code", "id_token"};
        List<String> scopesList = Arrays.asList(scopes);
        List<String> responsesList = Arrays.asList(responsesTypes);

        //REQUIRED  OIDC request params
        AuthorizationRequestUrl request = new AuthorizationRequestUrl(authorizationServerUrl, clientId, responsesList)
                .setRedirectUri(redirectUrl)
                .setScopes(scopesList)
                .setState(state)
                .set("nonce", ""); //TODO: nonce is mandatory we should try to generate one

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        //OPTIONAL OIDC request params
        if (scopesList.contains("offline_access")) {
            // If the list of scopes includes the special `offline_access` scope that enables issuing
            // of Refresh Tokens, we need to ask for consent by including this parameter.
            request.set("prompt", "consent");
        } else {
            // Tell the server to ask for login details again. This ensures that in case of multiple
            // accounts, the user won't accidentally authorise the wrong one.
            request.set("prompt", "login");
        }

        // An optional request parameter that asks the server to provide a touch-enabled interface.
        // Who knows, maybe the server is nice enough to make some changes.
        request.set("display", "touch");

        return request.build();
    }

    /**
     * Generates an Authentication Request URL to the Authorization Endpoint to start an Code Flow.
     * When using the Code Flow, all tokens are returned from the Token Endpoint.
     * The Authorization Server can authenticate the Client before exchanging the Authorization Code
     * for an Access Token.
     * @see <a href="http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">Code Flow</a>
     */
    public static String codeFlowAuthenticationUrl(String authorizationServerUrl, String clientId,
                                                   String redirectUrl, String[] scopes, String state,
                                                   Map<String,String> extras) {

        List<String> scopesList = Arrays.asList(scopes);

        AuthorizationCodeRequestUrl request = new AuthorizationCodeRequestUrl(authorizationServerUrl, clientId)
                .setRedirectUri(redirectUrl)
                .setScopes(scopesList)
                .setState(state)
                .set("nonce", "");//TODO: nonce is mandatory we should try to generate one

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        //OPTIONAL OIDC request params
        if (scopesList.contains("offline_access")) {
            // If the list of scopes includes the special `offline_access` scope that enables issuing
            // of Refresh Tokens, we need to ask for consent by including this parameter.
            request.set("prompt", "consent");
        } else {
            // Tell the server to ask for login details again. This ensures that in case of multiple
            // accounts, the user won't accidentally authorise the wrong one.
            request.set("prompt", "login");
        }

        // An optional request parameter that asks the server to provide a touch-enabled interface.
        // Who knows, maybe the server is nice enough to make some changes.
        request.set("display", "touch");

        return request.build();
    }


    public static String newAuthenticationUrl(String authorizationServerUrl, OIDCUtils.Flows flowType,
                                              String clientId, String redirectUrl, String[] scopes, String state) {

        return newAuthenticationUrl(authorizationServerUrl, flowType, clientId, redirectUrl, scopes, state, null);
    }

    public static String newAuthenticationUrl(String authorizationServerUrl, OIDCUtils.Flows flowType,
                                              String clientId, String redirectUrl, String[] scopes,
                                              String state, Map<String, String> extras) {
        String request;
        switch (flowType) {
            case Implicit: {
                request = implicitFlowAuthenticationUrl(authorizationServerUrl, clientId, redirectUrl, scopes, state, extras);
                break;
            }
            case Hybrid: {
                request = hybridFlowAuthenticationUrl(authorizationServerUrl, clientId, redirectUrl, scopes, state, extras);
                break;
            }
            case Code:
            default: {
                request = codeFlowAuthenticationUrl(authorizationServerUrl, clientId, redirectUrl, scopes, state, extras);
                break;
            }
        }
        return request;
    }

    /**
     * Exchanges an Authorization Code for an Access Token, Refresh Token and (optional) ID Token.
     * This provides the benefit of not exposing any tokens to the User Agent and possibly other
     * malicious applications with access to the User Agent.
     * The Authorization Server can also authenticate the Client before exchanging the Authorization
     * Code for an Access Token.
     *
     * Needs to be run on a separate thread.
     * @throws IOException
     */
    public static TokenResponse requestTokensWithCodeGrant(String tokenServerUrl, String redirectUrl,
                                                           String clientId, String clientSecret,
                                                           String authCode, boolean useOAuth2Only) throws IOException {
        return requestTokensWithCodeGrant(tokenServerUrl, redirectUrl, clientId, clientSecret, authCode, useOAuth2Only, null);
    }

    public static TokenResponse requestTokensWithCodeGrant(String tokenServerUrl, String redirectUrl,
                                                           String clientId, String clientSecret,
                                                           String authCode, boolean useOAuth2Only,
                                                           Map<String,String> extras) throws IOException {

        AuthorizationCodeTokenRequest request = new AuthorizationCodeTokenRequest(
                AndroidHttp.newCompatibleTransport(),
                new GsonFactory(),
                new GenericUrl(tokenServerUrl),
                authCode
        );
        request.setRedirectUri(redirectUrl);

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        if (!TextUtils.isEmpty(clientSecret)) {
            request.setClientAuthentication(new BasicAuthentication(clientId, clientSecret));
        } else {
            request.set("client_id", clientId);
        }

        // Working with OIDC
        if (useOAuth2Only) {
            Log.d("OIDCUtils", "tokens request OAuth2 sent");
            TokenResponse tokenResponse = request.executeUnparsed().parseAs(TokenResponse.class);
            String accessToken = tokenResponse.getAccessToken();

            if (!TextUtils.isEmpty(accessToken)){
                Log.d("OIDCUtils", String.format("Manage to parse and extract AT : %1$s", accessToken));
                return tokenResponse;
            }
            else {
                throw new IOException("Invalid Access Token returned.");
            }
        }
        else {
            Log.d("OIDCUtils", "tokens request OIDC sent");
            IdTokenResponse response = IdTokenResponse.execute(request);
            String idToken = response.getIdToken();

            if (isValidIdToken(clientId, idToken)) {
                return response;
            } else {
                throw new IOException("Invalid ID token returned.");
            }
        }
    }


    public static TokenResponse requestTokensWithPasswordGrant(String tokenServerUrl,String clientId, String clientSecret,
                                                               String[] scopes, String userName, String userPwd) throws IOException {
        return requestTokensWithPasswordGrant(tokenServerUrl, clientId, clientSecret, scopes, userName, userPwd, null);
    }

    public static TokenResponse requestTokensWithPasswordGrant(String tokenServerUrl,String clientId, String clientSecret,
                                                               String[] scopes, String userName, String userPwd,
                                                               Map<String,String> extras) throws IOException {

        List<String> scopesList = Arrays.asList(scopes);

        PasswordTokenRequest request = new PasswordTokenRequest(
                AndroidHttp.newCompatibleTransport(),
                new GsonFactory(),
                new GenericUrl(tokenServerUrl),
                userName,
                userPwd
        );

        if (!scopesList.isEmpty()) {
            request.setScopes(scopesList);
        }

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        if (!TextUtils.isEmpty(clientSecret)) {
            request.setClientAuthentication(new BasicAuthentication(clientId, clientSecret));
        } else {
            request.set("client_id", clientId);
        }


        // Working with OIDC
        if (scopesList.contains("openid")) {
            Log.d("OIDCUtils", "PasswordGrant request OIDC sent");

            IdTokenResponse tokenResponse = IdTokenResponse.execute(request);
            String idToken = tokenResponse.getIdToken();

            if (isValidIdToken(clientId, idToken)) {
                return tokenResponse;
            } else {
                throw new IOException("Invalid ID token returned.");
            }
        }
        // Working with OAuth2 only
        else {
            Log.d("OIDCUtils", "PasswordGrant request OAuth2 sent");
            TokenResponse tokenResponse = request.executeUnparsed().parseAs(TokenResponse.class);
            String accessToken = tokenResponse.getAccessToken();

            if (!TextUtils.isEmpty(accessToken)){
                Log.d("OIDCUtils", String.format("Manage to parse and extract AT : %1$s", accessToken));
                return tokenResponse;
            }
            else {
                throw new IOException("Invalid Access Token returned.");
            }
        }
    }



    /**
     * Exchanges a Refresh Token for a new set of tokens.
     *
     * Note that the Token Server may require you to use the `offline_access` scope to receive
     * Refresh Tokens.
     *
     */
    public static TokenResponse refreshTokens(String tokenServerUrl, String clientId, String clientSecret,
                                              String[] scopes, String refreshToken) throws IOException {
        return refreshTokens(tokenServerUrl, clientId, clientSecret, scopes, refreshToken, null);
    }

    public static TokenResponse refreshTokens(String tokenServerUrl, String clientId, String clientSecret,
                                              String[] scopes, String refreshToken, Map<String, String> extras) throws IOException {

        List<String> scopesList = Arrays.asList(scopes);

        RefreshTokenRequest request = new RefreshTokenRequest(
                AndroidHttp.newCompatibleTransport(),
                new GsonFactory(),
                new GenericUrl(tokenServerUrl),
                refreshToken
        );

        if (!scopesList.isEmpty()) {
            request.setScopes(scopesList);
        }

        // This are extra query parameters that can be specific to an OP. For instance for OpenAm
        // we can define 'realm' that defines to which sub realm the request is going to.
        if (extras != null) {
            for (Map.Entry<String, String> queryParam : extras.entrySet()) {
                request.set(queryParam.getKey(), queryParam.getValue());
            }
        }

        // If the oidc client is confidential (needs authentication)
        if (!TextUtils.isEmpty(clientSecret)) {
            request.setClientAuthentication(new BasicAuthentication(clientId, clientSecret));
        } else {
            request.set("client_id", clientId);
        }

        // Working with OIDC
        if (scopesList.contains("openid")) {
            return IdTokenResponse.execute(request);
        }
        else {
            return request.executeUnparsed().parseAs(TokenResponse.class);
        }
    }

    /**
     * Verifies an ID Token.
     * TODO: Look into verifying the token issuer as well?
     */
    public static boolean isValidIdToken(String clientId, String tokenString) throws IOException {

        List<String> audiences = Collections.singletonList(clientId);
        IdTokenVerifier verifier = new IdTokenVerifier.Builder()
                .setAudience(audiences)
                .setAcceptableTimeSkewSeconds(1000)
                .build();

        IdToken idToken = IdToken.parse(new GsonFactory(), tokenString);

        return verifier.verify(idToken);
    }

    /**
     * Gets user information from the UserInfo endpoint.
     */
    public static Map getUserInfo(String userInfoUrl, String idToken) throws IOException {
        return getUserInfo(userInfoUrl, idToken, null);
    }


    /**
     * Same as {@link OIDCUtils#getUserInfo(String, String)} but adds the realm field to the
     * userInfoUrl URL.
     * <br/>
     * <b>NOTE : This call is usually OpenAm specific.</b>
     */
    public static Map getUserInfo(String userInfoUrl, String idToken, Map<String,String> extras) throws IOException {
        if (extras != null) {
            HttpRequest.append(userInfoUrl, extras);
        }

        HttpRequest request = new HttpRequest(userInfoUrl, HttpRequest.METHOD_GET);
        request = prepareApiRequest(request, idToken);

        if (request.ok()) {
            String jsonString = request.body();
            return new Gson().fromJson(jsonString, Map.class);
        } else {
            throw new IOException(request.message());
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

    /**
     * Generates a TokenName that depends on the OIDC clientId. We use this so the same account can
     * carry tokens for different OIDC clients. For instance, Google uses this kind of system to
     * handle different access tokens to drive or gmail.
     * TODO: we should refactor all the calls using the static defaulTokenName for this (Authenticator#TOKEN_TYPE_ACCESS, Authenticator#TOKEN_TYPE_ID, Authenticator#TOKEN_TYPE_REFRESH)
     */
    public static String getTokenNameForClient(@NonNull String defaultTokenName, String clientId) {
        if (!TextUtils.isEmpty(defaultTokenName)){
            if (!TextUtils.isEmpty(clientId)){
                return String.format("%1$s.%2$s", defaultTokenName, clientId);
            }
            else {
                return defaultTokenName;
            }
        }
        else {
            throw new IllegalArgumentException("Parameter 'defaultTokenName' is null or empty");
        }
    }

    /**
     * Generates a secure state token
     * @param opName
     * @return
     */
    public static String generateStateToken(String opName){
        SecureRandom sr = new SecureRandom();
        String cleanOpName = TextUtils.replace(opName, new String[]{"\\W"}, new String[]{""}).toString();
        return  cleanOpName+sr.nextInt();
    }
}
