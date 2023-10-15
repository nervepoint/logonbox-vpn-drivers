package com.logonbox.vpn.drivers.lib;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermission;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.logonbox.vpn.drivers.lib.util.OsUtil;
import com.sshtools.liftlib.OS;

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
				return "linux-" + arch.resourcePathSuffix();
			case MAC_OS:
				return "macosx-" + arch.resourcePathSuffix();
			case WINDOWS:
				return "win32-" + arch.resourcePathSuffix();
			default:
				throw new UnsupportedOperationException();
			}
		}

		String librarySuffix() {
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
		WIREGUARD_GO, WG, NETWORK_CONFIGURATION_SERVICE, WIREGUARD;

		boolean searchPath() {
			switch (this) {
			case NETWORK_CONFIGURATION_SERVICE:
				return false;
			default:
				return true;
			}
		}
		
		boolean library() {
			switch(this) {
			case WIREGUARD:
				return true;
			default:
				return false;
			}
		}
		
		boolean deleteOnExit() {
			switch(this) {
			case WG:
				return true;
			default:
				return false;
			}
		}
		

		String[] dependencies() {
			switch (this) {
			case NETWORK_CONFIGURATION_SERVICE:
				return new String[] { "tunnel", "vcruntime140", "wireguard" };
			default:
				return new String[0];
			}
		}

		String libraryPath(String dep, OsName os, Arch arch) {
			return os.resourcePath(arch) + "/" + libraryFilename(dep, os);
		}

		String resourcePath(OsName os, Arch arch) {
			if(library())
				return os.resourcePath(arch) + "/" + libraryFilename(name(), os);
			else
				return os.resourcePath(arch) + "/" + exeFilename(os);
		}

		String toolFilename(OsName os) {
			if(library())
				return name().toLowerCase().replace('_', '-') + os.librarySuffix();
			else
				return name().toLowerCase().replace('_', '-') + os.executableSuffix();
		}

		String exeFilename(OsName os) {
			return name().toLowerCase().replace('_', '-') + os.executableSuffix();
		}

		String libraryFilename(String name, OsName os) {
			return name.toLowerCase().replace('_', '-') + os.librarySuffix();
		}
	}

	private Path tempCommandDir;
	private Map<Tool, Path> cache = new HashMap<>();

	public String tool(Tool tool) {
		try {
			synchronized (cache) {
				var path = cache.get(tool);

				if (path == null) {
					path = toolPath(tool);
					LOG.info("Tool {} found at {}.", tool, path);
					cache.put(tool, path);
				} else if (!Files.exists(path)) {
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

		var tempDir = binDir();
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
		var toolFilename = tool.exeFilename(os);
        var resourcePath = tool.resourcePath(os, arch);
		LOG.info("Extracting tool {} for platform {} on arch {} from {}", tool, os.name(), arch.name(), resourcePath);
		
		var res = find(os, arch, tool, resourcePath);
        if (res == null)
            throw new UnsupportedOperationException(
                    MessageFormat.format("The tool {0} is not supported on {1} {2}", tool, os, arch));
		var toolPath = extractFile(os, arch, tool, toolFilename, res, true);

		for (var dep : tool.dependencies()) {
			LOG.info("Extracting tool dependency {} for platform {} on arch {} from {}", dep, os.name(), arch.name(),
					resourcePath);
			var depPath = tool.libraryPath(dep, os, arch);
	        res = find(os, arch, tool, depPath);
			if (res == null)
				throw new UnsupportedOperationException(
						MessageFormat.format("The tool dependency {0} is not supported on {1} {2}", tool, os, arch));
			extractFile(os, arch, tool, tool.libraryFilename(dep, os), res, false);
		}

		return toolPath;
	}

    protected URL find(OsName os, Arch arch, Tool tool, String resourcePath) {
        var loader = Thread.currentThread().getContextClassLoader();
        if(loader != null) {
            LOG.info("Trying resource {} from context loader.", resourcePath, loader.getName());
        }
        var res = loader == null ? null : loader.getResource(resourcePath);
		if(res == null) {
            LOG.info("Trying resource {} from platform class loader.", resourcePath, NativeComponents.class.getName());
		    res = NativeComponents.class.getClassLoader().getResource(resourcePath);
		}
		if(res == null) {
            LOG.info("Trying resource {} from system class loader.", resourcePath, ClassLoader.getSystemClassLoader().getName());
            res = ClassLoader.getSystemClassLoader().getResource(resourcePath);
        }
        return res;
    }

	private Path extractFile(OsName os, Arch arch, Tool tool, String toolFilename, URL res, boolean execute)
			throws IOException {
		try (var in = res.openStream()) {

			var dir = binDir();

			Files.createDirectories(dir);

			var path = dir.resolve(toolFilename);
			try (var out = Files.newOutputStream(path)) {
				in.transferTo(out);
			}

			if(tool.deleteOnExit())
				path.toFile().deleteOnExit();
			if (os == OsName.WINDOWS) {
				path.toFile().setExecutable(execute, true);
			} else {
				if (execute)
					Files.setPosixFilePermissions(path,
							new LinkedHashSet<>(Arrays.asList(PosixFilePermission.OWNER_EXECUTE,
									PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
				else
					Files.setPosixFilePermissions(path, new LinkedHashSet<>(
							Arrays.asList(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
			}
			LOG.info("Extracted tool {} for platform {} on arch {} to {}", tool, os, arch, path);
			return path;
		}
	}

	public Path binDir() throws IOException {
		if (tempCommandDir == null) {
			tempCommandDir = Paths.get(System.getProperty("user.home")).resolve(".logonbox-vpn").resolve("bin");
			Files.createDirectories(tempCommandDir);
		}
		return tempCommandDir;
	}
}
