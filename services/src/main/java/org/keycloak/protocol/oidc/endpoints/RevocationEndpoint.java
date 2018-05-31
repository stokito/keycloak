/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.Consumes;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.POST;
import javax.ws.rs.core.*;

import java.util.List;

import static java.util.Arrays.asList;
import static org.keycloak.OAuth2Constants.*;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_OFFLINE;
import static org.keycloak.util.TokenUtil.TOKEN_TYPE_REFRESH;

/**
 * <a href="https://tools.ietf.org/html/rfc7009">RFC7009 OAuth 2.0 Token Revocation</aa>
 */
public class RevocationEndpoint {
    private static final Logger logger = Logger.getLogger(RevocationEndpoint.class);
    private static final List<String> SUPPORTED_TOKEN_TYPES = asList(TOKEN_TYPE_REFRESH, TOKEN_TYPE_OFFLINE, TOKEN_TYPE_BEARER);

    @Context
    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpRequest request;

    @Context
    private HttpHeaders headers;

    @Context
    private UriInfo uriInfo;

    private TokenManager tokenManager;
    private RealmModel realm;
    private EventBuilder event;

    public RevocationEndpoint(TokenManager tokenManager, RealmModel realm, EventBuilder event) {
        this.tokenManager = tokenManager;
        this.realm = realm;
        this.event = event;
    }


    /**
     * Logout a session via a non-browser invocation.
     * You must pass in the refresh or access token and authenticate the client if it is not public.
     *
     * If the client is a confidential client you must include the client-id and secret in an Basic Auth Authorization header.
     * If the client is a public client, then you must include a "client_id" form parameter.
     *
     * rfc7009 2.2. says "invalid tokens do not cause an error because purpose of the revocation request, invalidating the token, is already achieved".
     * Here is not separated when token format is invalid and when the token was already revoked (i.e. session was closed).
     * But from security respective it's better to cause an error in both situation because thus we can prevent mistakes in client code when it think that token was actually revoked while it's not.
     *
     * @return returns 200 if successful, 400 if not with a json error response.
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response revokeToken() {
        event.event(EventType.LOGOUT);

        checkSsl();
        checkRealm();
        ClientModel client = authorizeClient();

        MultivaluedMap<String, String> formParams = request.getDecodedFormParameters();
        String token = formParams.getFirst(PARAM_TOKEN);
        String tokenTypeHint = formParams.getFirst(PARAM_TOKEN_TYPE_HINT);

        try {
            revokeToken(token, tokenTypeHint);
        } catch (OAuthErrorException e) {
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(e.getError(), e.getDescription(), Response.Status.BAD_REQUEST);
        }
        return Cors.add(request, Response.ok()).auth().allowedOrigins(uriInfo, client).allowedMethods(HttpMethod.POST).exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS).build();
    }

    private void revokeToken(String token, String tokenTypeHint) throws OAuthErrorException {
        if (Validation.isBlank(token)) {
            event.error(Errors.INVALID_TOKEN);
            throw new OAuthErrorException(OAuthErrorException.INVALID_REQUEST, "Token not provided.");
        }

        if (Validation.isBlank(tokenTypeHint)) {
            tokenTypeHint = TOKEN_TYPE_HINT_REFRESH_TOKEN;
        }

        IDToken idToken = findIdToken(token, tokenTypeHint);
        if (idToken == null) {
            String anotherTokenType = tokenTypeHint.equals(TOKEN_TYPE_HINT_REFRESH_TOKEN) ? TOKEN_TYPE_HINT_ACCESS_TOKEN : TOKEN_TYPE_HINT_REFRESH_TOKEN;
            idToken = findIdToken(token, anotherTokenType);
        }

        validateTokenType(idToken.getType());
        boolean offline = TOKEN_TYPE_OFFLINE.equals(idToken.getType());
        boolean sessionIsOnline = closeSession(offline, idToken.getSessionState());
        if (!sessionIsOnline ) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_TOKEN, "Token expired or revoked");
        }
    }

    /**
     * RFC7009 2.2.1. Check that we support the revocation of the presented token type
     */
    private void validateTokenType(String tokenType) throws OAuthErrorException {
        if (!SUPPORTED_TOKEN_TYPES.contains(tokenType)) {
            throw new OAuthErrorException(OAuthErrorException.UNSUPPORTED_TOKEN_TYPE);
        }
    }

    private IDToken findIdToken(String token, String tokenType) throws OAuthErrorException {
        if (tokenType.equals(TOKEN_TYPE_HINT_REFRESH_TOKEN)) {
            return tokenManager.verifyRefreshToken(session, realm, token, true);
        } else {
            return tokenManager.verifyAccessToken(session, realm, token, true);
        }
    }

    private boolean closeSession(boolean offline, String sessionState) {
        UserSessionModel userSessionModel;
        if (offline) {
            UserSessionManager sessionManager = new UserSessionManager(session);
            userSessionModel = sessionManager.findOfflineUserSession(realm, sessionState);
        } else {
            userSessionModel = session.sessions().getUserSession(realm, sessionState);
        }

        boolean sessionIsOnline = userSessionModel != null;
        System.out.println("sessionIsOnline: " + userSessionModel);
        if (sessionIsOnline) {
            logout(userSessionModel, offline);
        }
        return sessionIsOnline ;
    }

    private void logout(UserSessionModel userSession, boolean offline) {
        AuthenticationManager.backchannelLogout(session, realm, userSession, uriInfo, clientConnection, headers, true, offline);
        event.user(userSession.getUser()).session(userSession).success();
    }

    private ClientModel authorizeClient() {
        ClientModel client = AuthorizeClientUtil.authorizeClient(session, event).getClient();

        if (client.isBearerOnly()) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_CLIENT, "Bearer-only not allowed", Response.Status.BAD_REQUEST);
        }

        return client;
    }

    private void checkSsl() {
        if (!uriInfo.getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new ErrorResponseException(OAuthErrorException.ACCESS_DENIED, "Realm not enabled", Response.Status.FORBIDDEN);
        }
    }
}
