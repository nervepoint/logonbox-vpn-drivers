/**
 * Copyright © 2023 LogonBox Limited (support@logonbox.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the “Software”), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.logonbox.vpn.drivers.lib.util;

import com.sshtools.liftlib.OS;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

public class OsUtil {
	public final static Logger LOG = LoggerFactory.getLogger(OsUtil.class);

	public static boolean doesCommandExist(String command) {
		return getPathOfCommandInPath(command) != null;
	}

	public static Path getPathOfCommandInPathOrFail(String command) throws IOException {
		Path p = getPathOfCommandInPath(command);
		if(p == null)
			throw new IOException("Could not location command '" + command + "'.");
		return p;
	}
	
	public static Path getPathOfCommandInPath(String command) {
		Set<String> path = new LinkedHashSet<>(Arrays.asList(System.getenv("PATH").split(File.pathSeparator)));
		if (OS.isMacOs()) {
			/* Hack for brew */
			path.add("/usr/local/bin");
		}
		for (String dir : path) {
			Path wg = Paths.get(dir, command);
			if (Files.exists(wg))
				return wg;
		}
		return null;
	}

	public static String[] debugCommandArgs(String... args) {
		LOG.debug("Executing commands: {}", String.join(" ", args));
		return args;
	}

    private static final boolean IS_64BIT = is64bit0();
    private static final boolean IS_AARCH64 = isAarch640();

    public static String getOS() {
    	if (OS.isWindows()) {
    		return "windows";
    	} else if (OS.isLinux()) {
    		return "linux";
    	} else if (OS.isMacOs()) {
    		return "osx";
    	} else {
    		return "other";
    	}
    }

    public static boolean is64bit() {
    	return IS_64BIT;
    }

    public static boolean isAarch64() {
    	return IS_AARCH64;
    }
    
    public static String getHostName() {
        return OS.isWindows() ? System.getenv("COMPUTERNAME") : System.getenv("HOSTNAME");
    }

    private static boolean is64bit0() {
    	String systemProp = System.getProperty("com.ibm.vm.bitmode");
    	if (systemProp != null) {
    		return "64".equals(systemProp);
    	}
    	systemProp = System.getProperty("sun.arch.data.model");
    	if (systemProp != null) {
    		return "64".equals(systemProp);
    	}
    	systemProp = System.getProperty("java.vm.version");
    	return systemProp != null && systemProp.contains("_64");
    }

    private static boolean isAarch640() {
    	return "aarch64".equals(System.getProperty("os.arch"));
    }

    public static InetSocketAddress parseInetSocketAddress(String addr) {
        return parseInetSocketAddress(addr, 0);
    }

    public static InetSocketAddress parseInetSocketAddress(String addr, int defaultPort) {
        var idx = addr.indexOf(':');
        if(idx == -1)
            return new InetSocketAddress(addr, defaultPort);
        else
            return new InetSocketAddress(addr.substring(0, idx), Integer.parseInt(addr.substring(idx + 1)));
    }
}
