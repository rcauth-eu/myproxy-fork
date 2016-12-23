package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/15 at  1:49 PM
 */
public abstract class BaseCommands extends ConfigurableCommandsImpl {

    public static final String CLIENTS = "clients";
    public static final String CLIENT_APPROVALS = "approvals";
    public static final String COPY = "copy";


    public abstract void about();

    public abstract ClientStoreCommands getNewClientStoreCommands() throws Exception;

    public abstract CopyCommands getNewCopyCommands() throws Exception;

    protected BaseCommands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getComponentName() {
        return OA4MPConfigTags.COMPONENT;
    }


    protected void start(String[] args) throws Exception {
        if (!getOptions(args)) {
            say("Warning: no configuration file specified. type in 'load --help' to see how to load one.");
            return;
        }
        initialize();
        about();
    }


    public ServiceEnvironment getServiceEnvironment() throws Exception {
        return (ServiceEnvironment) getEnvironment();
    }


    public ClientApprovalStoreCommands getNewClientApprovalStoreCommands() throws Exception {
        return new ClientApprovalStoreCommands(getMyLogger(), "  ", getServiceEnvironment().getClientApprovalStore());
    }

    @Override
    public boolean use(InputLine inputLine) throws Exception {
        CommonCommands commands = null;
        if (inputLine.hasArg(CLIENTS)) {
            commands = getNewClientStoreCommands();
        }
        if (inputLine.hasArg(CLIENT_APPROVALS)) {
            commands = getNewClientApprovalStoreCommands();
        }
        if (inputLine.hasArg(COPY)) {
            commands = getNewCopyCommands();
        }
        if (commands != null) {
            CLIDriver cli = new CLIDriver(commands);
            cli.start();
            return true;
        }

        if (super.use(inputLine)) {
            return true;
        }

        return false;
    }


    protected boolean hasComponent(String componentName) {
        return componentName.equals(CLIENTS) || componentName.equals(CLIENT_APPROVALS) || componentName.equals(COPY);
    }

    protected void runComponent(String componentName) throws Exception {
        CommonCommands commonCommands = null;
        if (componentName.equals(CLIENTS)) {
            commonCommands = getNewClientStoreCommands();
        }
        if (componentName.equals(CLIENT_APPROVALS)) {
            commonCommands = getNewClientApprovalStoreCommands();
        }
        if (componentName.equals(COPY)) {
            commonCommands = getNewCopyCommands();
        }
        if (commonCommands != null) {
            CLIDriver cli = new CLIDriver(commonCommands);
            cli.start();

        }
    }


    protected boolean executeComponent() throws Exception {
        if (hasOption(USE_COMPONENT_OPTION, USE_COMPONENT_LONG_OPTION)) {
            String component = getCommandLine().getOptionValue(USE_COMPONENT_OPTION);
            if (component != null && 0 < component.length()) {
                if (!hasComponent(component)) {
                    say("Unknown component name of \"" + component + "\". ");
                    return false;
                }
                runComponent(component);
                return true;
            } else {
                say("Caution, you specified using a component, but did not specify what the component is.");
            }
        }
        return false;
    }

    public void useHelp() {
        say("Choose the component you wish to use.");
        say("you specify the component as use + name. Supported components are");
        say(CLIENTS + " - edit client records");
        say(CLIENT_APPROVALS + " - edit client approval records\n");
        say(COPY + " - copy an entire store.\n");
        say("e.g.\n\nuse " + CLIENTS + "\n\nwill call up the client management component.");
        say("Type 'exit' when you wish to exit the component and return to the main menu");
    }

}
