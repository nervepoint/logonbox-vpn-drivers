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
        super(Collections.emptyMap(), Optional.empty(), Optional.empty(), Optional.empty());
        elevator = new Elevator.ElevatorBuilder().
                withReauthorizationPolicy(ReauthorizationPolicy.NEVER).
                build();
    }

    @Override
    public SystemCommands privileged() {
        if(OS.isAdministrator())
            return this;
        
        return new PrvilegedSystemCommands(this, env(), stdin(), stdout(), stderr());
    }

    @Override
    public void run(String... args) throws IOException {
        try {
            new BasicRun(this, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command. "  + e.getMessage(), e);
        }
    }

    @Override
    public Collection<String> output(String... args) throws IOException {
        try {
            return Arrays.asList(new Output(this, args).call());
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command. "  + e.getMessage(), e);
        }
    }

    @Override
    public Collection<String> silentOutput(String... args) {
        try {
            return Arrays.asList(new SilentOutput(this, args).call());
        } catch (RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new UncheckedIOException(new IOException("Failed to run command. " + e.getMessage(), e));
        }
    }

    @Override
    public int result(String... args) throws IOException {
        try {
            return new WithResult(this, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command."  + e.getMessage(), e);
        }
    }

    @Override
    public Collection<String> pipeTo(String content, String... args) throws IOException {
        try {
            return Arrays.asList(new PipeTo(this, content, args).call());
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command."  + e.getMessage(), e);
        }
    }

    @Override
    public int consume(Consumer<String> consumer, String... args) throws IOException {
        try {
            return new WithConsume(this, consumer, args).call();
        } catch (IOException | RuntimeException e) {
            throw e;
        }  catch (Exception e) {
            throw new IOException("Failed to run command. "  + e.getMessage(), e);
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

        PrvilegedSystemCommands(SystemCommands delegate, Map<String, String> env, Optional<ProcessRedirect> stdin, Optional<ProcessRedirect> stdout,
                Optional<ProcessRedirect> stderr) {
            super(env, stdin, stdout, stderr);
            this.delegate = delegate;
        }

        @Override
        public int result(String... args) throws IOException {
            try {
                return elevator.closure(new WithResult(this, args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command. "  + e.getMessage(), e);
            }
        }

        @Override
        public Collection<String> output(String... args) throws IOException {
            try {
                return Arrays.asList(elevator.closure(new Output(this, args)));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command. "  + e.getMessage(), e);
            }
        }

        @Override
        public Collection<String> silentOutput(String... args) {
            try {
                return Arrays.asList(elevator.closure(new SilentOutput(this, args)));
            } catch (RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new UncheckedIOException(new IOException("Failed to run command. "  + e.getMessage() , e));
            }
        }

        @Override
        public void run(String... args) throws IOException {
            try {
                elevator.closure(new BasicRun(this, args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command. "  + e.getMessage(), e);
            }
        }

        @Override
        public SystemCommands privileged() {
            return this;
        }

        @Override
        public Collection<String> pipeTo(String content, String... args) throws IOException {
            try {
                return Arrays.asList(elevator.closure(new PipeTo(this, content, args)));
            } catch (IOException | RuntimeException e) {
                e.printStackTrace();
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command. "  + e.getMessage(), e);
            }
        }

        @Override
        public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
            throw new UnsupportedOperationException();
        }

        @Override
        public int consume(Consumer<String> consumer, String... args) throws IOException {
            try {
                return elevator.closure(new WithConsume(this, consumer, args));
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run command. "  + e.getMessage(), e);
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
                return elevator.closure(task);
            } catch(UncheckedIOException uioe) {
            	throw uioe.getCause();
            } catch (IOException | RuntimeException e) {
                throw e;
            }  catch (Exception e) {
                throw new IOException("Failed to run task. "  + e.getMessage(), e);
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
            return new PrvilegedSystemCommands(this, env(), stdin(), stdout(), stderr());
        }

        @Override
        public Collection<String> pipeTo(String content, String... args) throws IOException {
            onLog.ifPresent(c -> c.accept(args));
            return delegate.pipeTo(content, args);
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

        @Override
        public SystemCommands stderr(ProcessRedirect redirect) {
            delegate.stderr(redirect);
            return this;
        }

        @Override
        public SystemCommands stdout(ProcessRedirect redirect) {
            delegate.stdout(redirect);
            return this;
        }

        @Override
        public SystemCommands stdin(ProcessRedirect redirect) {
            delegate.stdin(redirect);
            return this;
        }

        @Override
        public Optional<ProcessRedirect> stderr() {
            return delegate.stderr();
        }

        @Override
        public Optional<ProcessRedirect> stdout() {
            return delegate.stdout();
        }

        @Override
        public Optional<ProcessRedirect> stdin() {
            return delegate.stdin();
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
    public static abstract class AbstractProcessClosure<RET extends Serializable, EVT extends Serializable> implements ElevatedClosure<RET,EVT> {

        Env env;
        ProcessRedirect stdin, stdout, stderr;

        protected AbstractProcessClosure() {
        }

        AbstractProcessClosure(SystemCommands parent) {
            this.env = new Env(parent.env());
            this.stdin = parent.stdin().orElse(null);
            this.stdout = parent.stdout().orElse(null);
            this.stderr = parent.stderr().orElse(null);
        }

    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class BasicRun extends AbstractProcessClosure<Serializable, Serializable> {

        String[] args;

        public BasicRun() {
        }

        BasicRun(SystemCommands parent, String... args) {
            super(parent);
            this.args = args;
        }

        @Override
        public Serializable call(ElevatedClosure<Serializable,Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());
            bldr.redirectInput(stdin == null ? Redirect.INHERIT : stdin.toRedirect());
            bldr.redirectOutput(stdout == null ? Redirect.INHERIT : stdout.toRedirect());
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
    public final static class WithResult  extends AbstractProcessClosure<Integer, Serializable> {

        String[] args;

        public WithResult() {
        }

        WithResult(SystemCommands parent, String... args) {
            super(parent);
            this.args = args;
        }

        @Override
        public Integer call(ElevatedClosure<Integer, Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());
            bldr.redirectInput(stdin == null ? Redirect.INHERIT : stdin.toRedirect());
            bldr.redirectOutput(stdout == null ? Redirect.INHERIT : stdout.toRedirect());
            var process = bldr.start();
            return process.waitFor();
        }
    }

    @SuppressWarnings("serial")
    @Serialization
    public final static class Output extends AbstractProcessClosure<String[], Serializable> {

        String[] args;

        public Output() {
        }

        Output(SystemCommands parent, String... args) {
            super(parent);
            this.args = args;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());
            bldr.redirectInput(stdin == null ? Redirect.INHERIT : stdin.toRedirect());
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
    public final static class SilentOutput extends AbstractProcessClosure<String[], Serializable> {

        String[] args;

        public SilentOutput() {
        }

        SilentOutput(SystemCommands parent, String... args) {
            super(parent);
            this.args = args;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> proxy) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());
            bldr.redirectInput(stdin == null ? Redirect.INHERIT : stdin.toRedirect());
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
    public final static class PipeTo extends AbstractProcessClosure<String[], Serializable> {

        String[] args;
        String content;

        public PipeTo() {
        }

        PipeTo(SystemCommands parent, String content, String... args) {
            super(parent);
            this.args = args;
            this.content = content;
        }

        @Override
        public String[] call(ElevatedClosure<String[], Serializable> closure) throws Exception {
            var bldr = new ProcessBuilder(args);
            if (!env.isEmpty())
                bldr.environment().putAll(env);
            if(stderr == null)
            	bldr.redirectErrorStream(true);
            else
            	bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());

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
    public final static class WithConsume extends AbstractProcessClosure<Integer, String> {

        String[] args;
        transient Consumer<String> consumer;

        public WithConsume() {
        }

        WithConsume(SystemCommands parent, Consumer<String> consumer, String... args) {
            super(parent);
            this.args = args;
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
            bldr.redirectError(stderr == null ? Redirect.INHERIT : stderr.toRedirect());
            bldr.redirectInput(stdin == null ? Redirect.INHERIT : stdin.toRedirect());
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
