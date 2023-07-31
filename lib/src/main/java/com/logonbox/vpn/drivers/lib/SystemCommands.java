package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;

public interface SystemCommands {
    
    public static SystemCommands withEnv(Map<String, String> env, SystemCommands delegate) {
        return new SystemCommands() {
            
            private Map<String, String> thisEnv = env;
            
            @Override
            public Map<String, String> env() {
                return thisEnv;
            }

            @Override
            public int withResult(String... args) throws IOException {
                return delegate.withResult(args);
            }
            
            @Override
            public Collection<String> withOutput(String... args) throws IOException {
                return delegate.withOutput(args);
            }
            
            @Override
            public void run(String... args) throws IOException {
                delegate.run(args);
                
            }
            
            @Override
            public SystemCommands privileged() {
                return delegate.privileged();
            }
            
            @Override
            public void pipeTo(String content, String... args) throws IOException {
                delegate.pipeTo(content, args);
            }
            
            @Override
            public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
                return delegate.pipe(input, args);
            }
            
            @Override
            public SystemCommands env(Map<String, String> env) {
                this.thisEnv = env;
                return this;
            }
            
            @Override
            public int consume(Consumer<String> consumer, String... args) throws IOException {
                return delegate.consume(consumer, args);
            }
        };
    }
    
    default Map<String, String> env() {
        return Collections.emptyMap();
    }
    
    PrintWriter pipe(Consumer<String> input, String... args) throws IOException;

    SystemCommands privileged();

    default SystemCommands env(Map<String, String> env) {
        return withEnv(env, this);
    }

    void run(String... args) throws IOException;

    Collection<String> withOutput(String... args) throws IOException;

    int withResult(String... args) throws IOException;
    
    void pipeTo(String content, String... args) throws IOException;

    int consume(Consumer<String> consumer, String... args) throws IOException;

}
