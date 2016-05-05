package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import static edu.uiuc.ncsa.security.core.configuration.Configurations.*;

/**
 * A utility that loads the configuration from a node and has the tags, etc. for it.
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/16 at  8:50 AM
 */
public class LDAPConfigurationUtil {
    public static final String LDAP_TAG = "ldap";
    public static final String LDAP_PASSWORD_TAG = "password";
    public static final String LDAP_ADDRESS_TAG = "address";
    public static final String LDAP_SEARCH_BASE_TAG = "searchBase";
    public static final String LDAP_SEARCH_ATTRIBUTES_TAG = "searchAttributes";
    public static final String LDAP_SEARCH_ATTRIBUTE_TAG = "attribute";
    public static final String LDAP_SECURITY_PRINCIPAL_TAG = "principal";
    public static final String LDAP_PORT_TAG = "port";
    public static final String LDAP_ENABLED_TAG = "enabled";
    public static final int DEFAULT_PORT = 636;

    public static LDAPConfiguration getLdapConfiguration(MyLoggingFacade logger, ConfigurationNode node) {
        LDAPConfiguration ldapConfiguration = new LDAPConfiguration();
        logger.info("Starting to load LDAP configuration.");
        ConfigurationNode ldapNode = Configurations.getFirstNode(node, LDAP_TAG);


        if (ldapNode == null) {
            logger.info("No LDAP configuration found.");
            ldapConfiguration.setEnabled(false);
            return ldapConfiguration;
        }
        // There is a configuration, so implicitly enable this.
        ldapConfiguration.setEnabled(true);
        SSLConfiguration sslConfiguration = SSLConfigurationUtil.getSSLConfiguration(logger, ldapNode);
        ldapConfiguration.setSslConfiguration(sslConfiguration);
        //             sslKeystoreConfiguration.setKeystore(getFirstAttribute(cn2, SSL_KEYSTORE_PATH));

        ldapConfiguration.setServer(getNodeValue(ldapNode, LDAP_ADDRESS_TAG));
        ldapConfiguration.setSecurityPrincipal(getNodeValue(ldapNode, LDAP_SECURITY_PRINCIPAL_TAG));
        // Do stuff related to searching
        ConfigurationNode attributeNode = getFirstNode(ldapNode, LDAP_SEARCH_ATTRIBUTES_TAG);
        for (int i = 0; i < attributeNode.getChildrenCount(); i++) {
            // only get the elements tagged as attributes in case others get added in the future.
            if(LDAP_SEARCH_ATTRIBUTE_TAG.equals(attributeNode.getChild(i).getName())) {
                Object kid = attributeNode.getChild(i).getValue();
                if (kid != null) {
                    ldapConfiguration.getSearchAttributes().add(kid.toString());
                }
            }
        }

        ldapConfiguration.setSearchBase(getNodeValue(ldapNode, LDAP_SEARCH_BASE_TAG));
        ldapConfiguration.setPort(DEFAULT_PORT);

        String port = getNodeValue(ldapNode, LDAP_PORT_TAG);

        try {
            if (port != null) {
                ldapConfiguration.setPort(Integer.parseInt(port));
            }
        } catch (Throwable t) {
            logger.warn("Could not parse port \"" + port + "\" for the LDAP handler. Using default of " + DEFAULT_PORT);
        }

        ldapConfiguration.setPassword(getNodeValue(ldapNode, LDAP_PASSWORD_TAG));
        String x = getFirstAttribute(ldapNode, LDAP_ENABLED_TAG);
        if (x != null) {
            try {
                ldapConfiguration.setEnabled(Boolean.parseBoolean(x));
            } catch (Throwable t) {
                logger.warn("Could not parsed enabled flag value of \"" + x + "\". Assuming LDAP is enabled.");
            }
        }
        logger.info("LDAP configuration loaded.");

        return ldapConfiguration;
    }

}
