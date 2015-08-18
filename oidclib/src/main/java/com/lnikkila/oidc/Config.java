package com.lnikkila.oidc;

/**
 * Simple utility class for storing OpenID Connect provider endpoints configuration.
 */
public final class Config {

    // Supported OIDC Flows
    public enum Flows
    {
        Code,  				//http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
        Implicit,           //http://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth
        Hybrid,             //http://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth
        Password
    }

    // TODO: Add the OIDC endpoints information you received from your OIDC provider below.
    public static final String authorizationServerUrl = "https://www.example.com/oauth2/authorize";
    public static final String tokenServerUrl = "https://www.example.com/oauth2/token";
    public static final String userInfoUrl = "https://www.example.com/oauth2/userinfo";
}
