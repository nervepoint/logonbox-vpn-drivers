package com.logonbox.vpn.quick;

import com.sshtools.liftlib.Helper;

import org.slf4j.bridge.SLF4JBridgeHandler;

import java.util.Optional;
import java.util.concurrent.Callable;

import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

public abstract class AbstractCommand implements Callable<Integer> {

    public enum Level {
        TRACE, DEBUG, INFO, WARN, ERROR,
    }

    @Option(names = { "-L", "--log-level" }, paramLabel = "LEVEL", description = "Logging level for trouble-shooting.")
    private Optional<Level> level;

    @Option(names = { "--elevate" }, hidden = true, paramLabel = "SOCKET_PATH", description = "Run this as an elevated helper")
    private Optional<String> socketPath;

    @Option(names = { "-X", "--verbose-exceptions" }, description = "Show verbose exception traces on errors.")
    private boolean verboseExceptions;
    
    @Spec
    CommandSpec spec;

    @Override
    public final Integer call() throws Exception {
        initCommand();
        return onCall();
    }
    
    public final void initCommand() throws Exception {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level.orElse(Level.WARN).name());
        SLF4JBridgeHandler.removeHandlersForRootLogger();
        SLF4JBridgeHandler.install();
        if(socketPath.isPresent()) {
            Helper.main(new String[] { socketPath.get() });
            System.exit(0);
        }
    }
    
    boolean verboseExceptions() {
        return verboseExceptions;
    }
    
    protected abstract Integer onCall() throws Exception;
}
