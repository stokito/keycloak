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

package org.keycloak.testsuite.oauth;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.util.*;

import java.util.List;
import javax.ws.rs.core.Response.Status;

import org.keycloak.testsuite.util.OAuthClient.AccessTokenResponse;
import org.keycloak.testsuite.util.OAuthClient.TokenRevocationResponse;

import static org.junit.Assert.*;
import static org.keycloak.testsuite.admin.AbstractAdminTest.loadJson;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class RevocationEndpointTest extends AbstractKeycloakTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);

    @Before
    public void clientConfiguration() {
        ClientManager.realm(adminClient.realm("test")).clientId("test-app").directAccessGrant(true);
    }

    @Override
    public void addTestRealms(List<RealmRepresentation> testRealms) {
        RealmRepresentation realmRepresentation = loadJson(getClass().getResourceAsStream("/testrealm.json"), RealmRepresentation.class);
        RealmBuilder realm = RealmBuilder.edit(realmRepresentation).testEventListener();

        testRealms.add(realm.build());
    }

    @Test
    public void revokeRefreshToken() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String refreshTokenString = tokenResponse.getRefreshToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(refreshTokenString, "refreshT_token", "password");
        assertEquals(Status.OK.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeRefreshToken_no_hint() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String refreshTokenString = tokenResponse.getRefreshToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(refreshTokenString, null, "password");
        assertEquals(Status.OK.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeAccessToken() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String accessTokenString = tokenResponse.getAccessToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(accessTokenString, "access_token", "password");
        assertEquals(Status.OK.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeAccessToken_no_hint() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String accessTokenString = tokenResponse.getAccessToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(accessTokenString, null, "password");
        assertEquals(Status.OK.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeTokenStaleRefreshToken() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String refreshTokenString = tokenResponse.getRefreshToken();

        adminClient.realm("test").update(RealmBuilder.create().notBefore(Time.currentTime() + 10).build());

        // Logout should succeed with expired refresh token, see KEYCLOAK-3302
        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(refreshTokenString, "refreshT_token", "password");
        assertEquals(Status.BAD_REQUEST.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertEquals("Token expired or revoked", tokenRevocationResponse.getErrorDescription());
        assertEquals("invalid_token", tokenRevocationResponse.getError());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeTokenExpiredRefreshToken() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String refreshTokenString = tokenResponse.getRefreshToken();

        // Logout should succeed with expired ID token, see KEYCLOAK-3399
        setTimeOffset(60 * 60 * 24);
//        adminClient.realm("test").update(RealmBuilder.create().notBefore(Time.currentTime() + 10).build());

        // Logout should succeed with expired refresh token, see KEYCLOAK-3302
        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(refreshTokenString, "refreshT_token", "password");
        assertEquals(Status.BAD_REQUEST.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertEquals("Token expired or revoked", tokenRevocationResponse.getErrorDescription());
        assertEquals("invalid_token", tokenRevocationResponse.getError());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revokeIdToken() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String idTokenString = tokenResponse.getAccessToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(idTokenString, null, "password");
        assertEquals(Status.BAD_REQUEST.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertEquals("", tokenRevocationResponse.getErrorDescription());
        assertEquals("unsupported_token_type", tokenRevocationResponse.getError());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

    @Test
    public void revoke_incorrect_hint() throws Exception {
        oauth.doLogin("test-user@localhost", "password");

        String code = oauth.getCurrentQuery().get(OAuth2Constants.CODE);

        oauth.clientSessionState("client-session");
        AccessTokenResponse tokenResponse = oauth.doAccessTokenRequest(code, "password");
        String idTokenString = tokenResponse.getAccessToken();

        TokenRevocationResponse tokenRevocationResponse = oauth.doRevokeToken(idTokenString, "Some incorrect token type hint", "password");
        assertEquals(Status.BAD_REQUEST.getStatusCode(), tokenRevocationResponse.getStatusCode());
        assertEquals("", tokenRevocationResponse.getErrorDescription());
        assertEquals("invalid_token", tokenRevocationResponse.getError());
        assertNotNull(testingClient.testApp().getAdminLogoutAction());
    }

}
