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

	// Info: The endpoints configuration has move to 'oidclib/src/main/res/values/endpoint.xml'
}
