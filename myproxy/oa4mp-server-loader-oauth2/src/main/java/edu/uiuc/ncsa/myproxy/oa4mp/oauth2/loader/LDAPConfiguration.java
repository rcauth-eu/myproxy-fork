package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/3/16 at  11:17 AM
 */
public class LDAPConfiguration {
    String server;
    int port;
    SSLConfiguration sslConfiguration;

    public String getSecurityPrincipal() {
        return securityPrincipal;
    }

    public void setSecurityPrincipal(String securityPrincipal) {
        this.securityPrincipal = securityPrincipal;
    }

    String securityPrincipal;

    public String getSearchBase() {
        return searchBase;
    }

    public void setSearchBase(String searchBase) {
        this.searchBase = searchBase;
    }

    String searchBase;

    List<String> searchAttributes = new ArrayList<>();

    public List<String> getSearchAttributes() {
        return searchAttributes;
    }

    public void setSearchAttributes(List<String> searchAttributes) {
        this.searchAttributes = searchAttributes;
    }

    /**
     * If this is disabled (or there is no configuration for one) then the LDAP scope handler should
     * not be created, just a basic one.
     * @return
     */
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    boolean enabled = false;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    String password;

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public SSLConfiguration getSslConfiguration() {
        return sslConfiguration;
    }

    public void setSslConfiguration(SSLConfiguration sslConfiguration) {
        this.sslConfiguration = sslConfiguration;
    }
}
