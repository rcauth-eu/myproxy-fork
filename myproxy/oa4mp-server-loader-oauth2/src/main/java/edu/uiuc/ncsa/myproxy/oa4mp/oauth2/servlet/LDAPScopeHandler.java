package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.LDAPConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.LdapContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Hashtable;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/16 at  3:32 PM
 */
public class LDAPScopeHandler extends BasicScopeHandler {
    /**
     * Returns the name of the user for whom the search is to be run.
     * @param userInfo
     * @param request
     * @param transaction
     * @return
     */
    public String getSearchName(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) {
        return transaction.getUsername();
    }

    @Override
    synchronized public UserInfo process(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        if (!isLoggedOn()) {
            logon();
        }
        try {
            String searchName = getSearchName(userInfo, request, transaction);
            if (searchName != null) {
                if (getCfg().getSearchAttributes() == null) {

                    userInfo.getMap().putAll(simpleSearch(context, searchName, null));
                } else {
                    userInfo.getMap().putAll(simpleSearch(context, searchName, getCfg().getSearchAttributes().toArray(new String[]{})));

                }
            }
            context.close();
        } catch (CommunicationException ce) {
            getOa2SE().warn("Communication exception talking to LDAP.");
        } catch (Throwable e) {
            e.printStackTrace();
            if (getOa2SE().getMyLogger().isDebugOn()) {
                e.printStackTrace();
            }
            getOa2SE().getMyLogger().error("Error: Could not retrieve information from LDAP. Processing will continue.", e);
        } finally {
            closeConnection();
        }
        return userInfo;
    }


    protected boolean isLoggedOn() {
        return context != null;
    }

    LdapContext context;

    protected LDAPConfiguration getCfg() {
        return getOa2SE().getLdapConfiguration();
    }

    protected boolean logon() {
        try {
            System.setProperty("javax.net.ssl.trustStore", getCfg().getSslConfiguration().getTrustrootPath());
            System.setProperty("javax.net.ssl.trustStorePassword", getCfg().getSslConfiguration().getTrustRootPassword());

            // Set up the environment for creating the initial context
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            String providerUrl = "ldaps://" + getCfg().getServer();
            if (getCfg().getPort() != null) {
                providerUrl = providerUrl + ":" + getCfg().getPort();
            }
            env.put(Context.PROVIDER_URL, providerUrl);
            switch (getCfg().getAuthType()) {
                case LDAPConfigurationUtil.LDAP_AUTH_NONE_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_NONE);
                    env.put(Context.SECURITY_PROTOCOL, "ssl");

                    break;
                case LDAPConfigurationUtil.LDAP_AUTH_SIMPLE_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_SIMPLE);
                    env.put(Context.SECURITY_PRINCIPAL, getCfg().getSecurityPrincipal());
                    env.put(Context.SECURITY_CREDENTIALS, getCfg().getPassword());
                    env.put(Context.SECURITY_PROTOCOL, "ssl");
                    break;
                case LDAPConfigurationUtil.LDAP_AUTH_STRONG_KEY:
                    env.put(Context.SECURITY_AUTHENTICATION, LDAPConfigurationUtil.LDAP_AUTH_STRONG);
                    env.put(Context.SECURITY_PRINCIPAL, getCfg().getSecurityPrincipal());
                    env.put(Context.SECURITY_CREDENTIALS, getCfg().getPassword());
                    env.put(Context.SECURITY_PROTOCOL, "ssl");
                    break;
                default:
                case LDAPConfigurationUtil.LDAP_AUTH_UNSPECIFIED_KEY:
            }

            DirContext dirContext = new InitialDirContext(env);
            context = (LdapContext) dirContext.lookup(getCfg().getSearchBase());
            return context != null;
        } catch (Exception e) {
            if (getOa2SE().getMyLogger().isDebugOn()) {
                e.printStackTrace();
            }
            getOa2SE().getMyLogger().error("Error logging into LDAP server", e);
            return false;
        }
    }

    protected JSONObject simpleSearch(LdapContext ctx,
                                      String userID,
                                      String[] attributes) throws NamingException {
        SearchControls ctls = new SearchControls();
        if (attributes == null || attributes.length == 0) {
            // return everything if nothing is specified.
            ctls.setReturningAttributes(null);
        } else {
            ctls.setReturningAttributes(attributes);
        }
        String filter = "(&(uid=" + userID + "))";
        NamingEnumeration e = ctx.search(getCfg().getContextName(), filter, ctls);
        return toJSON(attributes, e);
    }

    /**
     * This takes the result of the search as a {@link NamingEnumeration} and set of attributes (from the
     * configuration file) and returns a JSON object. The default is that singletons are returned as simple
     * values while lists are recorded as arrays.
     * @param attributes
     * @param e
     * @return
     * @throws NamingException
     */
    protected JSONObject toJSON(String[] attributes, NamingEnumeration e) throws NamingException {
        JSONObject json = new JSONObject();

        while (e.hasMore()) {
            SearchResult entry = (SearchResult) e.next();
            Attributes a = entry.getAttributes();
            System.out.println(entry.getName());
            for (String attribID : attributes) {
                Attribute attribute = a.get(attribID);
                if(attribute == null){
                    continue;
                }
                if (attribute.size() == 1) {
                    // Single-valued attributes are recorded as simple values
                    json.put(attribID, attribute.get(0));
                } else {
                    // Multi-valued attributes are recorded as arrays.
                    JSONArray jsonAttribs = new JSONArray();
                    for (int i = 0; i < attribute.size(); i++) {
                        jsonAttribs.add(attribute.get(i));
                    }
                    json.put(attribID, jsonAttribs);
                }
            }
        }

        return json;
    }

    protected void closeConnection() {
        if (context != null) {
            try {
                context.close();
            } catch (Throwable t) {
                if (getOa2SE().getMyLogger().isDebugOn()) {
                    t.printStackTrace();
                }
                getOa2SE().getMyLogger().info("Exception trying to close LDAP connection: " + t.getMessage());
            }
        }
    }
}
