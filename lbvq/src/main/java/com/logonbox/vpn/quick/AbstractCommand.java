package com.logonbox.vpn.quick;

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

    @Option(names = { "-X", "--verbose-exceptions" }, description = "Show verbose exception traces on errors.")
    private boolean verboseExceptions;
    
    @Spec
    CommandSpec spec;

    @Override
    public final Integer call() throws Exception {
        setupLogging();
        return onCall();
    }
    
    public final void setupLogging() {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level.orElse(Level.WARN).name());
    }
    
    boolean verboseExceptions() {
        return verboseExceptions;
    }
    
    protected abstract Integer onCall() throws Exception;
}
