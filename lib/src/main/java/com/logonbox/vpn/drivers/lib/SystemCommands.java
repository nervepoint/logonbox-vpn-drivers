package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import com.sshtools.liftlib.ElevatedClosure;

public interface SystemCommands {
    
    public abstract class AbstractSystemCommands implements SystemCommands {
        private Map<String, String> env = new HashMap<>();
        
        protected AbstractSystemCommands(Map<String, String> env) {
            this.env.putAll(env);
        }

        @Override
        public final Map<String, String> env() {
            return env;
        }

        @Override
        public final SystemCommands env(Map<String, String> env) {
            this.env.putAll(env);
            return this;
        }
        
        
    }
    
//    public static SystemCommands withEnv(Map<String, String> env, SystemCommands delegate) {
//        return new SystemCommands() {
//            
//            private Map<String, String> thisEnv = env;
//            
//            @Override
//            public Map<String, String> env() {
//                return thisEnv;
//            }
//
//            @Override
//            public int result(String... args) throws IOException {
//                return delegate.result(args);
//            }
//            
//            @Override
//            public Collection<String> output(String... args) throws IOException {
//                return delegate.output(args);
//            }
//            
//            @Override
//            public void run(String... args) throws IOException {
//                delegate.run(args);
//                
//            }
//            
//            @Override
//            public SystemCommands privileged() {
//                return delegate.privileged();
//            }
//            
//            @Override
//            public void pipeTo(String content, String... args) throws IOException {
//                delegate.pipeTo(content, args);
//            }
//            
//            @Override
//            public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
//                return delegate.pipe(input, args);
//            }
//            
//            @Override
//            public SystemCommands env(Map<String, String> env) {
//                this.thisEnv = env;
//                return this;
//            }
//            
//            @Override
//            public int consume(Consumer<String> consumer, String... args) throws IOException {
//                return delegate.consume(consumer, args);
//            }
//
//            @Override
//            public void onLog(Consumer<String[]> commandLine) {
//                delegate.onLog(commandLine);
//            }
//
//            @Override
//            public SystemCommands logged() {
//                return delegate.logged();
//            }
//
//            @Override
//            public <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception {
//                return delegate.task(task);
//            }
//
//            @Override
//            public Collection<String> silentOutput(String... args) {
//                return delegate.silentOutput(args);
//            }
//        };
//    }
    
//    default Map<String, String> env() {
//        return Collections.emptyMap();
//    }
    
	Map<String, String> env();
	
    void onLog(Consumer<String[]> onLog);
    
    PrintWriter pipe(Consumer<String> input, String... args) throws IOException;

    SystemCommands privileged();

    SystemCommands logged();

    SystemCommands env(Map<String, String> env);
//    default SystemCommands env(Map<String, String> env) {
//        return withEnv(env, this);
//    }

    void run(String... args) throws IOException;

    Collection<String> output(String... args) throws IOException;

    Collection<String> silentOutput(String... args);

    int result(String... args) throws IOException;
    
    Collection<String> pipeTo(String content, String... args) throws IOException;

    int consume(Consumer<String> consumer, String... args) throws IOException;
    
    <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception;

}
