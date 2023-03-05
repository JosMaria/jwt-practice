package org.genesiscode.jwtpractice.config;

public class SecurityConstants {

    public static final String SECRET_KEY = "635166546A576E5A7234753778214125442A472D4B614E645267556B58703273";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";

    public static final long ONE_SECOND = 1000;
    public static final long ONE_MINUTE = ONE_SECOND * 60;
    public static final long ONE_HOUR = ONE_MINUTE * 60;
}
