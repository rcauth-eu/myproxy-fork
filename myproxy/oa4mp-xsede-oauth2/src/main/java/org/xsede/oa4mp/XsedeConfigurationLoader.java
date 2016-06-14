package org.xsede.oa4mp;

import java.util.Arrays;

import org.xsede.oa4mp.XsedeScopeHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandler;

import edu.uiuc.ncsa.security.core.configuration.Configurations;

import java.lang.ClassNotFoundException;
import java.lang.IllegalAccessException;
import java.lang.InstantiationException;

import org.apache.commons.configuration.tree.ConfigurationNode;

public class XsedeConfigurationLoader<T extends OA2SE> extends OA2ConfigurationLoader<T> {
    public XsedeConfigurationLoader(ConfigurationNode node) {
        super(node);
    }
    public XsedeConfigurationLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

    @Override
    public ScopeHandler getScopeHandler() throws ClassNotFoundException, IllegalAccessException, InstantiationException {
        if (0 < cn.getChildrenCount("xsedeApi".toString())) {

            ConfigurationNode node = Configurations.getFirstNode(cn, "xsedeApi".toString());
            ConfigurationNode username = Configurations.getFirstNode(node, "username".toString());
            ConfigurationNode password = Configurations.getFirstNode(node, "password".toString());

            scopeHandler = new XsedeScopeHandler(username.getValue().toString(), password.getValue().toString(), loggerProvider.get());
            // scopeHandler.setScopes(Arrays.asList("xsede"));
            scopeHandler.setScopes(getScopes()); // this is a complete list of scopes from the configuration file.
            return scopeHandler;
        } else {
            throw new InstantiationException("Couldn't find XUP API authentication credential");
        }
    }
}
