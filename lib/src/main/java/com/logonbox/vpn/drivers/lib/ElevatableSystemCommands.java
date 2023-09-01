package com.logonbox.vpn.drivers.lib;

import com.sshtools.liftlib.ElevatedClosure;
import com.sshtools.liftlib.Elevator;
import com.sshtools.liftlib.Elevator.ReauthorizationPolicy;
import com.sshtools.liftlib.OS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.lang.ProcessBuilder.Redirect;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import uk.co.bithatch.nativeimage.annotations.Serialization;

public class ElevatableSystemCommands extends SystemCommands.AbstractSystemCommands {
    
    private final Elevator elevator;
    private Optional<Consumer<String[]>> onLog = Optional.empty();
    
    public ElevatableSystemCommands() {
        super(Collections.emptyMap());
        elevator = new Elevator.ElevatorBuilder().
                withReauthorizationPolicy(ReauthorizationPolicy.NEVER).
                build();
    }

    @Override
    public SystemCommands privileged() {
        if(OS.isAdministrator())
            return this;
        
        return new PrvilegedSystemCommands(this, env());
    }

    @Override
    public void run(String... args) throws IOException {
        try {
            new BasicRun(new Env(env()), args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public Collection<String> output(String... args) throws IOException {
        try {
            return Arrays.asList(new Output(new Env(env()), args).call());
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public Collection<String> silentOutput(String... args) {
        try {
            return Arrays.asList(new SilentOutput(new Env(env()), args).call());
        } catch (RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new UncheckedIOException(new IOException("Failed to run command.", e));
        }
    }

    @Override
    public int result(String... args) throws IOException {
        try {
            return new WithResult(new Env(env()), args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public void pipeTo(String content, String... args) throws IOException {
        try {
            new PipeTo(new Env(env()), content, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public int consume(Consumer<String> consumer, String... args) throws IOException {
        try {
            return new WithConsume(new Env(env()), consumer, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override
    public void onLog(Consumer<String[]> onLog) {
        this.onLog = Optional.of(onLog);
    }

    @Override
    public SystemCommands logged() {
        return new LoggedSystemCommands(this);
    } 

    private final class PrvilegedSystemCommands extends AbstractSystemCommands {
        private SystemCommands delegate;

        PrvilegedSystemCommands(SystemCommands delegate, Map<String, String> env) {
            super(env);
            this.delegate = delegate;
        }

        @Override
        public int result(String... args) throws IOException {
            try {
                return elevator.call(new WithResult(new Env(env()), args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public Collection<String> output(String... args) throws IOException {
            try {
                return Arrays.asList(elevator.call(new Output(new Env(env()), args)));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public Collection<String> silentOutput(String... args) {
            try {
                return Arrays.asList(elevator.call(new SilentOutput(new Env(env()), args)));
            } catch (RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new UncheckedIOException(new IOException("Failed to run command.", e));
            }
        }

        @Override
        public void run(String... args) throws IOException {
            try {
                elevator.call(new BasicRun(new Env(env()), args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public SystemCommands privileged() {
            return this;
        }

        @Override
        public void pipeTo(String content, String... args) throws IOException {
            try {
                elevator.call(new PipeTo(new Env(env()), content, args));
            } catch (IOException | RuntimeException e) {
                e.printStackTrace();
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public int consume(Consumer<String> consumer, String... args) throws IOException {
            try {
                return elevator.call(new WithConsume(new Env(env()), consumer, args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public void onLog(Consumer<String[]> commandLine) {
            delegate.onLog(commandLine);
        }

        @Override
        public SystemCommands logged() {
            return new LoggedSystemCommands(this);
        }

        @Override
        public <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception {
            try {
                return elevator.call(task);
            } catch(UncheckedIOException uioe) {
            	throw uioe.getCause();
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run task.", e);
            }
        }
    }

    private final class LoggedSystemCommands implements SystemCommands {
        private SystemCommands delegate;

        LoggedSystemCommands(SystemCommands delegate) {
            this.delegate = delegate;
        }
        
        @Override
        public void run(String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            delegate.run(args);
        }

        @Override
        public int result(String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            return delegate.result(args);
        }

        @Override
        public SystemCommands privileged() {
            return new PrvilegedSystemCommands(this, env());
        }

        @Override
        public void pipeTo(String content, String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            delegate.pipeTo(content, args);
        }

        @Override
        public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            return delegate.pipe(input, args);
        }

        @Override
        public Collection<String> output(String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            return delegate.output(args);
        }

        @Override
        public Collection<String> silentOutput(String... args){
            onLog.ifPresent(c -> c.accept(args));
            return delegate.silentOutput(args);
        }

        @Override
        public void onLog(Consumer<String[]> onLog) {
            delegate.onLog(onLog);
        }

        @Override
        public SystemCommands logged() {
            return this;
        }

        @Override
        public int consume(Consumer<String> consumer, String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            return delegate.consume(consumer, args);
        }

        @Override
        public <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception {
            return delegate.task(task);
        }

		@Override
		public Map<String, String> env() {
			return delegate.env();
		}

		@Override
		public SystemCommands env(Map<String, String> env) {
			delegate.env(env);
			return this;
		}
    }
    
    @SuppressWarnings("serial")
    @Serialization
	public final static class Env extends HashMap<String, String> implements Serializable {
    	
    	public Env() {
    		super();
    	}
    	
    	public Env(Map<String, String> env) {
    		super(env);
    	}
    };

    @SuppressWarnings("serial")
    @Serialization
    public final static class BasicRun implements ElevatedClosure<Serializable, Serializable> {

        String[] args;
        Env env;

        public BasicRun() {
        }

        BasicRun(Env env, String... args) {
            this.args = args;
            this.env = env;
        }

        @Override
        public Serializable call(ElevatedClosure<Serializable,Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectOutput(Redirect.INHERIT);
            bldr.redirectInput(Redirect.INHERIT);
            var process = bldr.start();
            var result = process.waitFor();
            if (result != 0) {
                throw new IOException(MessageFormat.format("Command exited with non-zero status {0}", result));
            }
            return null;
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class WithResult implements ElevatedClosure<Integer, Serializable> {

        String[] args;
        Env env;

        public WithResult() {
        }

        WithResult(Env env, String... args) {
            this.args = args;
            this.env = env;
        }

        @Override
        public Integer call(ElevatedClosure<Integer, Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectOutput(Redirect.INHERIT);
            bldr.redirectInput(Redirect.INHERIT);
            var process = bldr.start();
            return process.waitFor();
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class Output implements ElevatedClosure<String[], Serializable> {

        String[] args;
        Env env;

        public Output() {
        }

        Output(Env env, String... args) {
            this.args = args;
            this.env = env;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectInput(Redirect.INHERIT);
            var process = bldr.start();
            String line = null;
            var reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            var lines = new ArrayList<String>();
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            try {
                int ret = process.waitFor();
                if (ret != 0)
                    throw new IllegalStateException("Unexpected return code. " + ret);
            } catch (InterruptedException ie) {
                throw new IOException("Interrupted.", ie);
            }
            return lines.toArray(new String[0]);
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class SilentOutput implements ElevatedClosure<String[], Serializable> {

        String[] args;
        Env env;

        public SilentOutput() {
        }

        SilentOutput(Env env, String... args) {
            this.args = args;
            this.env = env;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.DISCARD);
            bldr.redirectInput(Redirect.INHERIT);
            var process = bldr.start();
            String line = null;
            var reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            var lines = new ArrayList<String>();
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            try {
                process.waitFor();
            } catch (InterruptedException ie) {
                throw new IOException("Interrupted.", ie);
            }
            return lines.toArray(new String[0]);
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class PipeTo implements ElevatedClosure<String[], Serializable> {

        String[] args;
        Env env;
        String content;

        public PipeTo() {
        }

        PipeTo(Env env, String content, String... args) {
            this.args = args;
            this.env = env;
            this.content = content;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> closure) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectOutput(Redirect.INHERIT);

            var process = bldr.start();
            var output = new ArrayList<String>();
            try(var stdout = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                try (var stdin = process.getOutputStream()) {
                    stdin.write(content.getBytes());
                    stdin.flush();
                }
                String line;
                while( ( line = stdout.readLine() ) != null) {
                    output.add(line);
                }
            }
            try {
                int ret = process.waitFor();
                if (ret != 0)
                    throw new IllegalStateException("Unexpected return code. " + ret);
            } catch (InterruptedException ie) {
                throw new IOException("Interrupted.", ie);
            }
            return output.toArray(new String[0]);
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class WithConsume implements ElevatedClosure<Integer, String> {

        String[] args;
        Env env;
        transient Consumer<String> consumer;

        public WithConsume() {
        }

        WithConsume(Env env, Consumer<String> consumer, String... args) {
            this.args = args;
            this.env = env;
            this.consumer = consumer;
        }

        @Override
        public void event(String event) {
            consumer.accept(event);
        }

        @Override
        public Integer call(ElevatedClosure<Integer, String> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectInput(Redirect.INHERIT);
            var process = bldr.start();
            var reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = null;
            while ((line = reader.readLine()) != null) {
                proxy.event(line);
            }
            try {
                return process.waitFor();
            } catch (InterruptedException ie) {
                throw new IOException("Interrupted.", ie);
            }
        }
    }

    @Override
    public <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception {
        return task.call(task);
    }
}
