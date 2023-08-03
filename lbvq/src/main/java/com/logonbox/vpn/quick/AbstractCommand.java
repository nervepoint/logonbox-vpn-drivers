package com.logonbox.vpn.quick;

import java.util.Optional;
import java.util.concurrent.Callable;

import picocli.CommandLine.Option;

public abstract class AbstractCommand implements Callable<Integer> {

    public enum Level {
        TRACE, DEBUG, INFO, WARN, ERROR,
    }


    @Option(names = { "-L", "--log-level" }, paramLabel = "LEVEL", description = "Logging level for trouble-shooting.")
    private Optional<Level> level;

    @Override
    public final Integer call() throws Exception {
        setupLogging();
        return onCall();
    }
    
    public final void setupLogging() {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level.orElse(Level.WARN).name());
    }
    
    protected abstract Integer onCall() throws Exception;
}
