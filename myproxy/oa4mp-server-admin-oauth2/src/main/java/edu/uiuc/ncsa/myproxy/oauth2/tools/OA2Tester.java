package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.CLITester;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  2:51 PM
 */
public class OA2Tester extends CLITester {
    public OA2Tester(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ClientLoader<>(getConfigurationNode());
    }

    public static void main(String[] args) {
        try {
            OA2Tester testCommands = new OA2Tester(null);
            testCommands.start(args);
            OA2TestCommands usc = new OA2TestCommands(testCommands.getMyLogger(), (ClientEnvironment) testCommands.getEnvironment());

            CLIDriver cli = new CLIDriver(usc);
            cli.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void start(String[] args) throws Exception {
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        initialize();

    }
    public void about(){
            int width = 60;
            String stars = StringUtils.rightPad("", width + 1, "*");
            say(stars);
            say(padLineWithBlanks("* OA4MP2 OAuth 2/OIDC command line test client", width) + "*");
            say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
            say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
            say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
            say(padLineWithBlanks("*", width) + "*");
            say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
            say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
            say(stars);
    }

    @Override
    public boolean use(InputLine inputLine) throws Exception {
        String indent = "  ";
            if (inputLine.hasArg("test")) {
                OA2TestCommands usc = new OA2TestCommands(getMyLogger(), (ClientEnvironment) getEnvironment());
                CLIDriver cli = new CLIDriver(usc);
                cli.start();
                return true;
            }
        return false;
    }
}
