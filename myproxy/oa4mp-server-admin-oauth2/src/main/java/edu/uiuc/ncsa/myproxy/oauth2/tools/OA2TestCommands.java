package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.TestCommands;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2Asset;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2MPService;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;
import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:57 PM
 */
public class OA2TestCommands extends TestCommands {
    public OA2TestCommands(MyLoggingFacade logger, ClientEnvironment ce) {
        super(logger, ce);
    }

    OA2MPService service;

    protected OA2MPService getOA2S() {
        return (OA2MPService) getService();
    }

    @Override
    public OA2MPService getService() {
        if (service == null) {
            service = new OA2MPService(getCe());
        }
        return service;
    }

    public void getURIHelp() {
        say("Usage: This will create the correct URL to pass to your browser.");
        say("       This URL should be pasted exactly into the location bar.");
        say("       You must then authenticate. After you authenticate, the");
        say("       service will attempt a call back to a client endpoint which will");
        say("       fail (this is the hook that lets us do this manually).");
        say("       Nest Step: You should invoke getAuthGrant using this to get an authorization grant.");
    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getRandomString() {
        long ll = secureRandom.nextLong();
        return Long.toHexString(ll);
    }

    /**
     * Constructs the URI
     *
     * @param inputLine
     * @throws Exception
     */
    public void geturi(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getURIHelp();
            return;
        }
        /*
        https://test.cilogon.org/authorize?
        state=qqqqq&response_type=code&
        redirect_uri=https%3A%2F%2Fashigaru.ncsa.uiuc.edu%3A9443%2Fclient2%2Fready&
        scope=openid%20edu.uiuc.ncsa.myproxy.getcert&
        nonce=n-0S6_WzA2Mj&
        client_id=myproxy:oa4mp,2012:/client_id/35679e1eb48281eb8cd98cfa6a57fa16&
        client_secret=KcG54c03XnhIw3FU9qjYzAnvUdYdqWxLouKW-euqpNHwQZAKk5wNOuFVxWJrngnHV-WnsbMuSlvc9CnUiX9rSZB7oFB7rcb_zT2GxlBZ7NlJSOsttcfm-AaN0wWGXYXrR1pJ7yVocHPTw0rX0sre_CySQnh98Kfz8Ngsg0kGlkMocnks785fg3sXtYVFVNMKqM8Cj6qZQI3Ja5q0QNm6XUJw4mmrRIonkMmyqBMq60F5gu9e4x0laDTc0-exLKxRVQmBBovsyffiAwxwTR7salNB3VK5g8ZeMWbHmrSN5swzc_YbTn8RskvFHDcy6jSl92aUoD_9yMxvsrkhUhO9wc_c
         */
 /*       String callback = getCe().getCallback().toString();
        HashMap<String, String> args = new HashMap<>();
        args.put(OA2Constants.STATE, getRandomString());
        args.put(OA2Constants.NONCE, getRandomString());
        args.put(OA2Constants.RESPONSE_TYPE, "code");
        args.put(OA2Constants.REDIRECT_URI, callback);
        args.put(OA2Constants.SCOPE, getOA2S().getRequestedScopes());
        args.put(OA2Constants.CLIENT_ID, getCe().getClientId());
        args.put(OA2Constants.PROMPT, "login");
        say(createURI(getCe().getAuthorizationUri().toString(), args));
 */
        Identifier id = AssetStoreUtil.createID();
        OA4MPResponse resp = getService().requestCert(id);
        dummyAsset = (OA2Asset) getCe().getAssetStore().get(id.toString());
        say(resp.getRedirect().toString());
    }

    protected String createURI(String base, HashMap<String, String> args) throws UnsupportedEncodingException {
        String uri = base;
        boolean firstPass = true;
        for (String key : args.keySet()) {
            String value = args.get(key);
            uri = uri + (firstPass ? "?" : "&") + key + "=" + encode(value);
            if (firstPass) firstPass = false;
        }
        canGetGrant = true;
        return uri;
    }

    static String encoding = "UTF-8";

    String encode(String x) throws UnsupportedEncodingException {
        if (x == null) return "";
        return URLEncoder.encode(x, encoding);
    }

    String decode(String x) throws UnsupportedEncodingException {
        if (x == null) return "";
        return URLDecoder.decode(x, encoding);
    }

    AuthorizationGrant grant;

    public void setgrant(InputLine inputLine) throws Exception {
/*
        if(!canGetGrant){
            say("Sorry, but you have not generated a uri and possibly authenticated. Please do that first.");
            return;
        }
*/
        if (inputLine.size() != 2 || showHelp(inputLine)) {
            getGrantHelp();
            return;
        }
        String x = inputLine.getArg(1); // zero-th element is the name of this function. 1st is the actual argument.
        // now we parse this.
        if (!x.startsWith(getCe().getCallback().toString())) {
            say("The callback in the configuration does not match that in the argument you gave");
            return;
        }
        String args = x.substring(x.indexOf("?") + 1); // skip the ? in the substring.
        StringTokenizer st = new StringTokenizer(args, "&");
        while (st.hasMoreTokens()) {
            String current = st.nextToken();
            if (current.startsWith("code=")) {
                URI uri = URI.create(decode(current.substring(5)));
                say("grant=" + uri.toString()); // length of string "code="
                grant = new AuthorizationGrantImpl(uri);
            }
        }
    }

    public OA2Asset getDummyAsset() {
        return dummyAsset;
    }

    public void clear(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getClearHelp();
            return;
        }
        dummyAsset = null;
        currentATResponse = null;
        grant = null;

        canGetCert = false;
        canGetGrant = false;
        canGetRT = false;
        canGetAT = false;
    }

    boolean canGetGrant = false;
    boolean canGetAT = false;
    boolean canGetCert = false;
    boolean canGetRT = false;

    protected void getClearHelp() {
        say("clear: reset all internal state and restart. You should do this rather than just restarting the process");
        say("       as you may run into old state.");
    }

    OA2Asset dummyAsset;

    public void getat(InputLine inputLine) throws Exception {
       /* if(!canGetAT){
            say("Sorry, but you have not gotten a grant yet here, so you cannot get an access token.");
        }*/
        if (grant == null || showHelp(inputLine)) {
            getATHelp();
            return;
        }

        currentATResponse = getOA2S().getAccessToken(getDummyAsset(), grant);
        printTokens();
/*
        say(" access token = " + currentATResponse.getAccessToken().getToken());
        say("refresh token = " + currentATResponse.getRefreshToken().getToken());
        say("   expires in = " + currentATResponse.getRefreshToken().getExpiresIn() + "ms.");
*/
    }

    ATResponse2 currentATResponse;

    protected void getCertHelp() {
        say("getcert: This will get the requested cert chain from the server.");
    }

    protected void getUIHelp() {
        say("getuserinfo: This will get the user info from the server. You must have already authenticated");
        say("             *and* gotten a valid access token by this point. Just a list of these it printed.");
    }

    public void getuserinfo(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getUIHelp();
            return;
        }

        UserInfo userInfo = getOA2S().getUserInfo(dummyAsset.getIdentifier().toString());
        say("user info:");
        for (String key : userInfo.getMap().keySet()) {
            say("          " + key + " = " + userInfo.getMap().get(key));
        }

    }

    public void getcert(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getCertHelp();
            return;
        }
        AssetResponse assetResponse = getOA2S().getCert(dummyAsset, currentATResponse);
        say("returned username=" + assetResponse.getUsername());
        say("X509Certs:");
        say(CertUtil.toPEM(assetResponse.getX509Certificates()));

    }

    protected void getRTHelp(){
        say("getrt: Get a new refresh token. You must have already called getat to have gotten an access token");
        say("       first. This will print out ");
    }
    protected void printTokens(){
        say(" access token = " + dummyAsset.getAccessToken().getToken());
        say("refresh token = " + dummyAsset.getRefreshToken().getToken());
        say("RT expires in = " + dummyAsset.getRefreshToken().getExpiresIn() + " ms.");
        Date startDate = DateUtils.getDate(dummyAsset.getRefreshToken().getToken());
        startDate.setTime(startDate.getTime() + dummyAsset.getRefreshToken().getExpiresIn());
        say("   expires at " + startDate);

    }
    public void getrt(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            getRTHelp();
            return;
        }

        dummyAsset = getOA2S().refresh(dummyAsset.getIdentifier().toString());
        // Have to update the AT reponse here every time or no token state is preserved.
        currentATResponse = new ATResponse2(dummyAsset.getAccessToken(), dummyAsset.getRefreshToken());
        printTokens();
    }


    protected void getATHelp() {
        say("getat: Gets the access token and refresh token for a given grant. Your argument is the out put from");
        say("       the getgrant call here.");
    }

    protected void getGrantHelp() {
        say("getgrant: The assumption is that you use geturi to get the correct authorization uri and have ");
        say("          logged in. Your browser *should* have a call back to your client. Cut and paste that");
        say("          as the argument to this call. This will return a string with the grant in it. You can use");
        say("          that to get an access token.");
    }
}
