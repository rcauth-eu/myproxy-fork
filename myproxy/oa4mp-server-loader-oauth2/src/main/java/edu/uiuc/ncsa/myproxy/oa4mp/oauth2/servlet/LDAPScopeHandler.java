package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import org.ldaptive.Connection;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.DefaultConnectionFactory;
import org.ldaptive.LdapException;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.http.HttpServletRequest;
import java.util.Hashtable;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/16 at  3:32 PM
 */
public class LDAPScopeHandler extends BasicScopeHandler {
    @Override
    public UserInfo process(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        ConnectionFactory connFactory = new DefaultConnectionFactory("ldap://directory.ldaptive.org");
        Connection conn = null;
        try {
            conn = connFactory.getConnection();
        } catch (LdapException e) {
            e.printStackTrace();
        }
        try {
          // open the connection to the ldap
          conn.open();

          // perform an operation on the connection
        } catch (LdapException e) {
            e.printStackTrace();
        } finally {
          // close the connection to the ldap
          conn.close();
        }

        return userInfo;
    }

    public static void main(String[] args){
        logon();
    }
    protected static boolean logon(){
        try
             {
                 // Set up the environment for creating the initial context
                 Hashtable<String, String> env = new Hashtable<String, String>();
                 env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
                 env.put(Context.PROVIDER_URL, "ldap://co.cilogon.org:666");
                 //
                 env.put(Context.SECURITY_AUTHENTICATION, "simple");
                 env.put(Context.SECURITY_PRINCIPAL, "domain\\user"); //we have 2 \\ because it's a escape char
                 env.put(Context.SECURITY_CREDENTIALS, "test");

                 // Create the initial context

                 DirContext ctx = new InitialDirContext(env);
                 boolean result = ctx != null;

                 if(ctx != null)
                     ctx.close();

                 return result;
             }
             catch (Exception e)
             {
                 e.printStackTrace();
                 return false;
             }
    }
}
