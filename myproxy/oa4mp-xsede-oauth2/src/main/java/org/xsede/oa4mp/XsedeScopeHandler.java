package org.xsede.oa4mp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import javax.ws.rs.core.HttpHeaders;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import javax.json.Json;
import javax.json.JsonReader;
import javax.json.JsonObject;

import org.apache.http.util.EntityUtils;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.BasicScopeHandler;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes.SCOPE_PROFILE;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes.SCOPE_EMAIL;

import java.util.logging.Logger;

/**
 * XsedeScopeHandler
 *
 */
public class XsedeScopeHandler extends BasicScopeHandler { 
    public static final String SCOPE_XSEDE = "xsede";

    String OA4MP_USER = "username";
    String OA4MP_PASSWORD = "password";
    MyLoggingFacade myLogger;

    public XsedeScopeHandler(String Username, String Password, MyLoggingFacade logger) {
        super();
        OA4MP_USER = Username;
       	OA4MP_PASSWORD = Password;
        myLogger = logger;
    }

    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException
    {
        OA2ServiceTransaction t = (OA2ServiceTransaction) transaction;

        myLogger.info("In XSEDE scope handler3: " + getScopes());

        String subject = userInfo.getSub();

        if (subject == null) {
            // throw new UnsupportedScopeException("No subject was found");
            return userInfo; // nothing can be done without subject info
        }

        String auth = OA4MP_USER + ":" + OA4MP_PASSWORD;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("ISO-8859-1")));
        String authHeader = "Basic " + new String(encodedAuth);

        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpPost postRequest = new HttpPost(
            "https://api.xsede.org/tokens/v1");
        postRequest.addHeader("accept", "application/json");

        postRequest.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

        try {
            HttpResponse response = httpClient.execute(postRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : "
                   + response.getStatusLine().getStatusCode());
            }

            JsonReader rdr = Json.createReader(response.getEntity().getContent());
            JsonObject obj = rdr.readObject();
            String token = obj.getJsonArray("result".toString()).getJsonObject(0).getString("token".toString());

            auth = OA4MP_USER + ":" + token;
            encodedAuth = Base64.encodeBase64(auth.getBytes(Charset.forName("ISO-8859-1")));
            authHeader = "Basic " + new String(encodedAuth);

            httpClient = new DefaultHttpClient();
            HttpGet getRequest = new HttpGet("https://api.xsede.org/profile/v1" + "/" + subject);
            getRequest.addHeader("accept", "application/json");

            getRequest.setHeader(HttpHeaders.AUTHORIZATION, authHeader);

            response = httpClient.execute(getRequest);

            if (response.getStatusLine().getStatusCode() != 200) {
                throw new RuntimeException("Failed : HTTP error code : "
                   + response.getStatusLine().getStatusCode());
            }

            // Get user record for "subject" using "token" for password.

            rdr = Json.createReader(response.getEntity().getContent());
            obj = rdr.readObject();
            JsonObject profile = obj.getJsonArray("result".toString()).getJsonObject(0);
            String firstName = profile.getString("first_name".toString());
            String middleName = profile.getString("middle_name".toString());
            String lastName = profile.getString("last_name".toString());
            String email = profile.getString("email".toString());
            String organization = profile.getString("organization".toString());

            if (t.getScopes().contains(SCOPE_PROFILE)) {
                myLogger.info("Processing profile scope in XSEDE handler");
                userInfo.setGiven_name(firstName);
                userInfo.setMiddle_name(middleName);
                userInfo.setFamily_name(lastName);
            }

            if (t.getScopes().contains(SCOPE_EMAIL)) {
                myLogger.info("Processing email scope in XSEDE handler");
                userInfo.setEmail(email);
            }

            if (t.getScopes().contains(SCOPE_XSEDE)) {
                myLogger.info("Processing xsede scope in XSEDE handler");
                userInfo.put("xsedeHomeOrganization".toString(), organization);
            }
        } catch (IOException E) {
            throw new UnsupportedScopeException("IOException");
        }

        return userInfo;
    }
}
