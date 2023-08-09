package com.logonbox.vpn.drivers.lib;

import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.sshtools.liftlib.OS;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

public class NativeComponents {
    final static Logger LOG = LoggerFactory.getLogger(NativeComponents.class);

    public enum Arch {
        X86, X86_64, AARCH64;

        String resourcePathSuffix() {
            switch (this) {
            case X86:
                return "x86";
            case X86_64:
                return "x86-64";
            case AARCH64:
                return "aarch64";
            default:
                throw new UnsupportedOperationException();
            }
        }
    }

    public enum OsName {
        WINDOWS, MAC_OS, LINUX;

        String resourcePath(Arch arch) {
            switch (this) {
            case LINUX:
                return "/linux-" + arch.resourcePathSuffix();
            case MAC_OS:
                return "/macosx-" + arch.resourcePathSuffix();
            case WINDOWS:
                return "/win32-" + arch.resourcePathSuffix();
            default:
                throw new UnsupportedOperationException();
            }
        }
        
        String dependencySuffix() {
            switch (this) {
            case WINDOWS:
                return ".dll";
            case MAC_OS:
                return ".dylib";
            default:
                return ".so";
            }
        }

        String executableSuffix() {
            switch (this) {
            case WINDOWS:
                return ".exe";
            default:
                return "";
            }
        }
    }

    public enum Tool {
        WIREGUARD_GO, WG, NETWORK_CONFIGURATION_SERVICE;

        boolean searchPath() {
            switch (this) {
            case NETWORK_CONFIGURATION_SERVICE:
                return false;
            default:
                return true;
            }
        }
        
        String[] dependencies() {
            switch(this) {
            case NETWORK_CONFIGURATION_SERVICE:
                return new String[] { "tunnel", "vcruntime140", "wireguard" };
            default:
                return new String[0];
            }
        }

        String resourcePath(OsName os, Arch arch) {
            return os.resourcePath(arch) + "/" + toolFilename(os);
        }

        String toolFilename(OsName os) {
            return name().toLowerCase().replace('_', '-') + os.executableSuffix();
        }
    }

    private Path tempCommandDir;
    private Map<Tool, Path> cache = new HashMap<>();
    private final PlatformService<?> platform;
    
    NativeComponents(PlatformService<?> platform) {
        this.platform = platform;
    }

    public String tool(Tool tool) {
        try {
            synchronized (cache) {
                var path = cache.get(tool);
                

                
                if (path == null) {
                    path = toolPath(tool);
                    LOG.info("Tool {} found at {}.", tool, path);
                    cache.put(tool, path);
                }
                else if(!Files.exists(path)) {
                    LOG.warn("It looks like the tool {} has disappeared. Attempting to re-extract.", tool);
                    path = toolPath(tool);
                    cache.put(tool, path);
                    
                }
                return path.toString();
            }
        } catch (IOException ioe) {
            throw new UncheckedIOException(ioe);
        }
    }

    private Path toolPath(Tool tool) throws IOException {
        var os = os();
        var toolFilename = tool.toolFilename(os);

        if (tool.searchPath()) {
            var path = OsUtil.getPathOfCommandInPath(toolFilename);
            if (path != null)
                return path;
        }

        var tempDir = getTempCommandDir();
        var path = tempDir.resolve(toolFilename);
        if (Files.exists(path)) {
            return path;
        }

        return extractCommand(os, arch(), tool);
    }

    private OsName os() {
        if (OS.isLinux()) {
            return OsName.LINUX;
        } else if (OS.isWindows()) {
            return OsName.WINDOWS;
        } else if (OS.isMacOs()) {
            return OsName.MAC_OS;
        } else {
            throw new UnsupportedOperationException();
        }
    }

    private Arch arch() {
        if (OsUtil.isAarch64())
            return Arch.AARCH64;
        else if (OsUtil.is64bit())
            return Arch.X86_64;
        else
            return Arch.X86;
    }

    private Path extractCommand(OsName os, Arch arch, Tool tool) throws IOException {
        var toolFilename = tool.toolFilename(os);
        var resourcePath = tool.resourcePath(os, arch);
        LOG.info("Extracting tool {} for platform {} on arch {} from {}", tool, os.name(),
                arch.name(), resourcePath);
        var res = platform.getClass().getResource(resourcePath);
        if (res == null)
            throw new UnsupportedOperationException(
                    MessageFormat.format("The tool {0} is not supported on {1} {2}", tool, os, arch));
        try (var in = res.openStream()) {

            var dir = getTempCommandDir();

            Files.createDirectories(dir);

            var path = dir.resolve(toolFilename);
            try (var out = Files.newOutputStream(path)) {
                in.transferTo(out);
            }

            path.toFile().deleteOnExit();
            Files.setPosixFilePermissions(path, new LinkedHashSet<>(Arrays.asList(PosixFilePermission.OWNER_EXECUTE,
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            LOG.info("Extracted tool {} for platform {} on arch {} to {}", tool, os, arch, path);
            return path;
        }
    }

    private Path getTempCommandDir() throws IOException {
        if (tempCommandDir == null)
            tempCommandDir = Files.createTempDirectory("vpn");
        return tempCommandDir;
    }
}
