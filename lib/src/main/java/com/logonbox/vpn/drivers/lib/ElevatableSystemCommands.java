package com.logonbox.vpn.drivers.lib;

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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import com.sshtools.liftlib.ElevatedClosure;
import com.sshtools.liftlib.Elevator;
import com.sshtools.liftlib.Elevator.ReauthorizationPolicy;
import com.sshtools.liftlib.OS;

import uk.co.bithatch.nativeimage.annotations.Serialization;

public class ElevatableSystemCommands implements SystemCommands {
    
    private final Elevator elevator;
    private Optional<Consumer<String[]>> onLog = Optional.empty();
	private Map<String, String> env = new HashMap<>();
    
    public ElevatableSystemCommands() {
        elevator = new Elevator.ElevatorBuilder().
                withReauthorizationPolicy(ReauthorizationPolicy.NEVER).
                build();
    }

    @Override
    public SystemCommands privileged() {
        if(OS.isAdministrator())
            return this;
        
        return new PrvilegedSystemCommands(this);
    }

    @Override
    public void run(String... args) throws IOException {
        try {
            new BasicRun(env(), args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public Collection<String> output(String... args) throws IOException {
        try {
            return Arrays.asList(new Output(env(), args).call());
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public Collection<String> silentOutput(String... args) {
        try {
            return Arrays.asList(new SilentOutput(env(), args).call());
        } catch (RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new UncheckedIOException(new IOException("Failed to run command.", e));
        }
    }

    @Override
    public int result(String... args) throws IOException {
        try {
            return new WithResult(env(), args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public void pipeTo(String content, String... args) throws IOException {
        try {
            new PipeTo(env(), content, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command.", e);
        }
    }

    @Override
    public int consume(Consumer<String> consumer, String... args) throws IOException {
        try {
            return new WithConsume(env(), consumer, args).call();
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

    private final class PrvilegedSystemCommands implements SystemCommands {
        private SystemCommands delegate;

        public PrvilegedSystemCommands(SystemCommands delegate) {
            this.delegate = delegate;
        }

        @Override
        public int result(String... args) throws IOException {
            try {
                return elevator.call(new WithResult(env(), args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public Collection<String> output(String... args) throws IOException {
            try {
                return Arrays.asList(elevator.call(new Output(env(), args)));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public Collection<String> silentOutput(String... args) {
            try {
                return Arrays.asList(elevator.call(new SilentOutput(env(), args)));
            } catch (RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new UncheckedIOException(new IOException("Failed to run command.", e));
            }
        }

        @Override
        public void run(String... args) throws IOException {
            try {
                elevator.call(new BasicRun(env(), args));
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
                elevator.call(new PipeTo(env(), content, args));
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
                return elevator.call(new WithConsume(env(), consumer, args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command.", e);
            }
        }

        @Override
        public Map<String, String> env() {
            return delegate.env();
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

		@Override
		public SystemCommands env(Map<String, String> env) {
			delegate.env(env);
			return this;
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
            return new PrvilegedSystemCommands(this);
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
		public SystemCommands env(Map<String, String> env) {
			delegate.env(env);
			return this;
		}

		@Override
		public Map<String, String> env() {
			return delegate.env();
		}
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class BasicRun implements ElevatedClosure<Serializable, Serializable> {

        String[] args;
        Map<String, String> env;

        public BasicRun() {
        }

        BasicRun(Map<String, String> env, String... args) {
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
        Map<String, String> env;

        public WithResult() {
        }

        WithResult(Map<String, String> env, String... args) {
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
        Map<String, String> env;

        public Output() {
        }

        Output(Map<String, String> env, String... args) {
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
        Map<String, String> env;

        public SilentOutput() {
        }

        SilentOutput(Map<String, String> env, String... args) {
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
    public final static class PipeTo implements ElevatedClosure<Serializable, Serializable> {

        String[] args;
        Map<String, String> env;
        String content;

        public PipeTo() {
        }

        PipeTo(Map<String, String> env, String content, String... args) {
            this.args = args;
            this.env = env;
            this.content = content;
        }

        @Override
        public Serializable call(ElevatedClosure<Serializable, Serializable> closure) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(Redirect.INHERIT);
            bldr.redirectOutput(Redirect.INHERIT);

            var process = bldr.start();
            try (var stdin = process.getOutputStream()) {
                stdin.write(content.getBytes());
                stdin.flush();
            }
            try {
                int ret = process.waitFor();
                if (ret != 0)
                    throw new IllegalStateException("Unexpected return code. " + ret);
            } catch (InterruptedException ie) {
                throw new IOException("Interrupted.", ie);
            }
            return null;
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class WithConsume implements ElevatedClosure<Integer, String> {

        String[] args;
        Map<String, String> env;
        transient Consumer<String> consumer;

        public WithConsume() {
        }

        WithConsume(Map<String, String> env, Consumer<String> consumer, String... args) {
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

	@Override
	public Map<String, String> env() {
		return env;
	}

	@Override
	public SystemCommands env(Map<String, String> env) {
		this.env  = env;
		return this;
	}
}
