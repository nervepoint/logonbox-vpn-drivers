package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.lang.ProcessBuilder.Redirect;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import com.sshtools.liftlib.ElevatedClosure;

public interface SystemCommands {

    public abstract class AbstractSystemCommands implements SystemCommands {
        private Map<String, String> env = new HashMap<>();
        private Optional<Redirect> stdin;
        private Optional<Redirect> stdout;
        private Optional<Redirect> stderr;

        protected AbstractSystemCommands(Map<String, String> env, Optional<Redirect> stdin, Optional<Redirect> stdout,
                Optional<Redirect> stderr) {
            this.env.putAll(env);
            this.stdin = stdin;
            this.stdout = stdout;
            this.stderr = stderr;
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

        @Override
        public SystemCommands stderr(Redirect stderr) {
            this.stderr = Optional.of(stderr);
            return this;
        }

        @Override
        public SystemCommands stdout(Redirect stdout) {
            this.stdout = Optional.of(stdout);
            return this;
        }

        @Override
        public SystemCommands stdin(Redirect stdin) {
            this.stdin = Optional.of(stdin);
            return this;
        }

        @Override
        public Optional<Redirect> stderr() {
            return stderr;
        }

        @Override
        public Optional<Redirect> stdout() {
            return stdout;
        }

        @Override
        public Optional<Redirect> stdin() {
            return stdin;
        }

    }

    Map<String, String> env();

    void onLog(Consumer<String[]> onLog);

    PrintWriter pipe(Consumer<String> input, String... args) throws IOException;

    SystemCommands privileged();

    SystemCommands logged();

    SystemCommands env(Map<String, String> env);

    SystemCommands stderr(Redirect redirect);

    SystemCommands stdout(Redirect redirect);

    SystemCommands stdin(Redirect redirect);

    Optional<Redirect> stderr();

    Optional<Redirect> stdout();

    Optional<Redirect> stdin();

    void run(String... args) throws IOException;

    Collection<String> output(String... args) throws IOException;

    Collection<String> silentOutput(String... args);

    int result(String... args) throws IOException;

    Collection<String> pipeTo(String content, String... args) throws IOException;

    int consume(Consumer<String> consumer, String... args) throws IOException;

    <R extends Serializable> R task(ElevatedClosure<R, Serializable> task) throws Exception;

}
