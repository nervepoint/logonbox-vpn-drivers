package com.logonbox.vpn.drivers.lib;

import com.sshtools.forker.client.EffectiveUserFactory.DefaultEffectiveUserFactory;
import com.sshtools.forker.client.ForkerBuilder;
import com.sshtools.forker.client.OSCommand;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;

public class UnprivilegedSystemCommands implements SystemCommands {

    @Override
    public SystemCommands privileged() {
        return new SystemCommands() {

            @Override
            public int withResult(String... args) throws IOException {
                return callWithEnv(env(), () -> OSCommand.adminCommand(args));
            }

            @Override
            public Collection<String> withOutput(String... args) throws IOException {
                return callWithEnv(env(), () -> OSCommand.adminCommandAndCaptureOutput(args));
            }

            @Override
            public void run(String... args) throws IOException {
                runWithEnv(env(), () -> OSCommand.admin(args));
            }

            @Override
            public SystemCommands privileged() {
                return this;
            }

            @Override
            public void pipeTo(String content, String... args) throws IOException {
                doPipeTo(env(), content, new ForkerBuilder(args)
                        .effectiveUser(DefaultEffectiveUserFactory.getDefault().administrator()));
            }

            @Override
            public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
                return doPipe(env(), input, new ForkerBuilder(args)
                        .effectiveUser(DefaultEffectiveUserFactory.getDefault().administrator()));
            }

            @Override
            public int consume(Consumer<String> consumer, String... args) throws IOException {
                return doConsume(env(), consumer, new ForkerBuilder(args)
                        .effectiveUser(DefaultEffectiveUserFactory.getDefault().administrator()));
            }

            @Override
            public Map<String, String> env() {
                return UnprivilegedSystemCommands.this.env();
            }
        };
    }

    interface IORunnable {
        void run() throws IOException;
    }

    interface IOCallable<T> {
        T call() throws IOException;
    }

    static void runWithEnv(Map<String, String> env, IORunnable runnable) throws IOException {
        if (env.isEmpty())
            runnable.run();
        else {
            var was = OSCommand.environment();
            try {
                runnable.run();
            } finally {
                OSCommand.environment(was);
            }
        }
    }

    static <T> T callWithEnv(Map<String, String> env, IOCallable<T> runnable) throws IOException {
        if (env.isEmpty())
            return runnable.call();
        else {
            var was = OSCommand.environment();
            try {
                return runnable.call();
            } finally {
                OSCommand.environment(was);
            }
        }
    }

    @Override
    public void run(String... args) throws IOException {
        runWithEnv(env(), () -> OSCommand.run(args));
    }

    @Override
    public Collection<String> withOutput(String... args) throws IOException {
        return callWithEnv(env(), () -> OSCommand.runCommandAndCaptureOutput(args));
    }

    @Override
    public int withResult(String... args) throws IOException {
        return callWithEnv(env(), () -> OSCommand.runCommand(args));
    }

    @Override
    public void pipeTo(String content, String... args) throws IOException {
        doPipeTo(env(), content, new ForkerBuilder(args));
    }

    @Override
    public int consume(Consumer<String> consumer, String... args) throws IOException {
        return doConsume(env(), consumer, new ForkerBuilder(args));
    }

    @Override
    public PrintWriter pipe(Consumer<String> input, String... args) throws IOException {
        return doPipe(env(), input, new ForkerBuilder(args));
    }

    private static PrintWriter doPipe(Map<String, String> env, Consumer<String> input, ForkerBuilder fb)
            throws IOException {
        if (!env.isEmpty()) {
            fb.environment().putAll(env);
        }
        fb.redirectErrorStream(true);
        var process = fb.start();
        var thread = new Thread(() -> {
            try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    input.accept(line);
                }
            } catch (IOException ioe) {
            }
        });
        var out = new PrintWriter(process.getOutputStream(), true) {
            @Override
            public void close() {
                try {
                    super.close();
                }
                finally {
                    try {
                        if(process.waitFor() != 0) {
                            throw new UncheckedIOException(new IOException(String.format("scutil exited with non-zero code %d.", process.exitValue())));
                        }
                    } catch (InterruptedException e) {
                        throw new UncheckedIOException(new IOException("Interrupted.", e));
                    } 
                }
            }
            
        };
        thread.start();
        return out;
    }

    private static int doConsume(Map<String, String> env, Consumer<String> consumer, ForkerBuilder fb)
            throws IOException {
        if (!env.isEmpty()) {
            fb.environment().putAll(env);
        }
        fb.redirectErrorStream(true);
        var process = fb.start();
        var reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line = null;
        while ((line = reader.readLine()) != null) {
            consumer.accept(line);
        }
        try {
            return process.waitFor();
        } catch (InterruptedException ie) {
            throw new IOException("Interrupted.", ie);
        }
    }

    private static void doPipeTo(Map<String, String> env, String content, ForkerBuilder fb) throws IOException {
        if (!env.isEmpty()) {
            fb.environment().putAll(env);
        }
        fb.redirectErrorStream(true);
        var p = fb.start();
        try (var stdin = p.getOutputStream()) {
            p.getOutputStream().write(content.getBytes());
            p.getOutputStream().flush();
        }
        p.getInputStream().transferTo(System.out);
        try {
            int ret = p.waitFor();
            if (ret != 0)
                throw new IllegalStateException("Unexpected return code. " + ret);
        } catch (InterruptedException ie) {
            throw new IOException("Interrupted.", ie);
        }
    }

//    public void command(String... args) throws IOException {
//        OSCommand.run(args);
//    }
//    
//    public  Collection<String> commandWithOutput(String... args) throws IOException {
//        return OSCommand.runAndCaptureOutput(args);
//    }
//    
//    public int privilegedWithResult(String... args) throws IOException {
//        OSCommand.adminCommand(args);
//    }
//    
//    public  Collection<String> privilegedWithOutput(String... args) throws IOException {
//        return OSCommand.adminCommandAndCaptureOutput(args);
//    }
//    
//    public void privileged(String... args) throws IOException {
//        OSCommand.admin(args);
//    }
//
//    @Override
//    public SystemCommands privileged() {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public void run(String... args) throws IOException {
//        // TODO Auto-generated method stub
//        
//    }
//
//    @Override
//    public Collection<String> withOutput(String... args) throws IOException {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public int withResult(String... args) throws IOException {
//        // TODO Auto-generated method stub
//        return 0;
//    }
//
//    @Override
//    public void pipeTo(String content, String... commands) throws IOException {
//        ForkerBuilder fb = new ForkerBuilder(commands);
//        fb.redirectErrorStream(true);
//        Process p = fb.start();
//        try(OutputStream stdin = p.getOutputStream()) {
//            p.getOutputStream().write(content.getBytes());
//            p.getOutputStream().flush();    
//        }
//        p.getInputStream().transferTo(System.out);
//        try {
//        int ret = p.waitFor();
//        if(ret != 0)
//            throw new IllegalStateException("Unexpected return code. " + ret);
//        }
//        catch(InterruptedException ie) {
//            throw new IOException("Interrupted.", ie);
//        }
//    }
//
//    @Override
//    public SystemCommands env(Map<String, String> env) {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public Collection<String> pipeToWithOutput(String content, String... args) throws IOException {
//        // TODO Auto-generated method stub
//        return null;
//    }
//
//    @Override
//    public int consume(Consumer<String> consumer, String... args) throws IOException {
//        // TODO Auto-generated method stub
//        return 0;
//    }
//    
//    private void updateResolvConf(String[] dns) throws IOException {
//        ForkerBuilder b = new ForkerBuilder("resolvconf", "-a", getPlatform().resolvconfIfacePrefix() + getName(), "-m",
//                "0", "-x");
//        b.redirectErrorStream(true);
//        b.io(IO.IO);
//        b.effectiveUser(EffectiveUserFactory.getDefault().administrator());
//        ForkerProcess p = b.start();
//        try (PrintWriter pw = new PrintWriter(p.getOutputStream(), true)) {
//            pw.println(String.format("nameserver %s", String.join(" ", dns)));
//        }
//        String res = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
//        int v;
//        try {
//            v = p.waitFor();
//        } catch (InterruptedException e) {
//            throw new IOException(String.format("Failed to set DNS. %s", res), e);
//        }
//        if (StringUtils.isNotBlank(res) || v != 0)
//            throw new IOException(String.format("Failed to set DNS. Exit %d. %s", v, res));
//    }
}
