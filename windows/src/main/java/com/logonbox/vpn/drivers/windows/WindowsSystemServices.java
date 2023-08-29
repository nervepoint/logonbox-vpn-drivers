package com.logonbox.vpn.drivers.windows;

import java.io.Closeable;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledFuture;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Structure.FieldOrder;
import com.sun.jna.platform.win32.Advapi32;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.Kernel32Util;
import com.sun.jna.platform.win32.W32Service;
import com.sun.jna.platform.win32.W32ServiceManager;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinBase.PROCESS_INFORMATION;
import com.sun.jna.platform.win32.WinBase.STARTUPINFO;
import com.sun.jna.platform.win32.WinDef.DWORD;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.platform.win32.WinNT.HANDLE;
import com.sun.jna.platform.win32.Winsvc;
import com.sun.jna.platform.win32.Winsvc.SC_HANDLE;
import com.sun.jna.platform.win32.Winsvc.SERVICE_STATUS_HANDLE;
import com.sun.jna.platform.win32.Winsvc.SERVICE_STATUS_PROCESS;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.win32.W32APIOptions;
import com.sun.jna.win32.W32APITypeMapper;

public class WindowsSystemServices implements Closeable {

	/**
	 * Extension the JNA Platform's {@link Advapi32} that adds some functions
	 * required by Forker.
	 */
	public interface XAdvapi32 extends Advapi32 {

		class QUERY_SERVICE_CONFIG extends Structure {
			public DWORD dwServiceType;
			public DWORD dwStartType;
			public DWORD dwErrorControl;
			public char[] lpBinaryPathName;
			public char[] lpLoadOrderGroup;
			public DWORD dwTagId;
			public char[] lpDependencies;
			public char[] lpServiceStartName;
			public char[] lpDisplayName;

			QUERY_SERVICE_CONFIG() {
			}

			QUERY_SERVICE_CONFIG(int size) {
				lpBinaryPathName = new char[256];
				lpLoadOrderGroup = new char[256];
				lpDependencies = new char[256];
				lpServiceStartName = new char[256];
				lpDisplayName = new char[256];

				allocateMemory(size);
			}
		}

		/**
		 */
		public static class SID_IDENTIFIER_AUTHORITY extends Structure {

			/**
			 */
			public byte[] Value = new byte[6];

			@Override
			protected List<String> getFieldOrder() {
				return Arrays.asList(new String[] { "Value" });
			}
		}

		/**
		 * Log on, then load the user's profile in the HKEY_USERS registry key. The
		 * function returns after the profile has been loaded. Loading the profile can
		 * be time-consuming, so it is best to use this value only if you must access
		 * the information in the HKEY_CURRENT_USER registry key.
		 * 
		 * Windows Server 2003: The profile is unloaded after the new process has been
		 * terminated, regardless of whether it has created child processes.
		 */
		public final static int LOGON_WITH_PROFILE = 0x00000001;
		/**
		 * Log on, but use the specified credentials on the network only. The new
		 * process uses the same token as the caller, but the system creates a new logon
		 * session within LSA, and the process uses the specified credentials as the
		 * default credentials.
		 * 
		 * This value can be used to create a process that uses a different set of
		 * credentials locally than it does remotely. This is useful in inter-domain
		 * scenarios where there is no trust relationship.
		 * 
		 * The system does not validate the specified credentials. Therefore, the
		 * process can start, but it may not have access to network resources.
		 */
		public final static int LOGON_NETCREDENTIALS_ONLY = 0x00000002;
		/**
		 * The new process does not inherit the error mode of the calling process.
		 * Instead, the new process gets the current default error mode. An application
		 * sets the current default error mode by calling SetErrorMode.
		 * 
		 * This flag is enabled by default.
		 */
		public final static int CREATE_DEFAULT_ERROR_MODE = 0x04000000;
		/**
		 * The new process has a new console, instead of inheriting the parent's
		 * console. This flag cannot be used with the DETACHED_PROCESS flag.
		 * 
		 * This flag is enabled by default.
		 */
		public final static int CREATE_NEW_CONSOLE = 0x00000010;
		/**
		 * The new process is the root process of a new process group. The process group
		 * includes all processes that are descendants of this root process. The process
		 * identifier of the new process group is the same as the process identifier,
		 * which is returned in the lpProcessInfo parameter. Process groups are used by
		 * the GenerateConsoleCtrlEvent function to enable sending a CTRL+C or
		 * CTRL+BREAK signal to a group of console processes.
		 * 
		 * This flag is enabled by default.
		 */
		public final static int CREATE_NEW_PROCESS_GROUP = 0x00000200;
		/**
		 * This flag is only valid starting a 16-bit Windows-based application. If set,
		 * the new process runs in a private Virtual DOS Machine (VDM). By default, all
		 * 16-bit Windows-based applications run in a single, shared VDM. The advantage
		 * of running separately is that a crash only terminates the single VDM; any
		 * other programs running in distinct VDMs continue to function normally. Also,
		 * 16-bit Windows-based applications that run in separate VDMs have separate
		 * input queues. That means that if one application stops responding
		 * momentarily, applications in separate VDMs continue to receive input.
		 */
		public final static int CREATE_SEPARATE_WOW_VDM = 0x00000800;
		/**
		 * The primary thread of the new process is created in a suspended state, and
		 * does not run until the ResumeThread function is called.
		 */
		public final static int CREATE_SUSPENDED = 0x00000004;
		/**
		 * Indicates the format of the lpEnvironment parameter. If this flag is set, the
		 * environment block pointed to by lpEnvironment uses Unicode characters.
		 * Otherwise, the environment block uses ANSI characters.
		 */
		public final static int CREATE_UNICODE_ENVIRONMENT = 0x00000400;

		/**
		 * The process is a console application that is being run without a console
		 * window. Therefore, the console handle for the application is not set.
		 * 
		 * This flag is ignored if the application is not a console application, or if
		 * it is used with either CREATE_NEW_CONSOLE or DETACHED_PROCESS.
		 */
		public final static int CREATE_NO_WINDOW = 0x08000000;

		/**
		 * The process is created with extended startup information; the lpStartupInfo
		 * parameter specifies a STARTUPINFOEX structure.
		 * 
		 * Windows Server 2003: This value is not supported.
		 */
		public final static int EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

		/**
		 * Instance
		 */
		XAdvapi32 INSTANCE = Native.load("Advapi32", XAdvapi32.class, W32APIOptions.UNICODE_OPTIONS);

		/**
		 * @param pIdentifierAuthority pIdentifierAuthority
		 * @param bytSubAuthorityCount bytSubAuthorityCount
		 * @param intSubAuthority0     intSubAuthority0
		 * @param intSubAuthority1     intSubAuthority1
		 * @param intSubAuthority2     intSubAuthority2
		 * @param intSubAuthority3     intSubAuthority3
		 * @param intSubAuthority4     intSubAuthority4
		 * @param intSubAuthority5     intSubAuthority5
		 * @param intSubAuthority6     intSubAuthority6
		 * @param intSubAuthority7     intSubAuthority7
		 * @param pSid                 pSid
		 * @return status
		 */
		public boolean AllocateAndInitializeSid(SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
				byte bytSubAuthorityCount, int intSubAuthority0, int intSubAuthority1, int intSubAuthority2,
				int intSubAuthority3, int intSubAuthority4, int intSubAuthority5, int intSubAuthority6,
				int intSubAuthority7, Pointer pSid);

		/**
		 * Creates a new process and its primary thread. The new process runs in the
		 * security context of the specified token. It can optionally load the user
		 * profile for the specified user.
		 *
		 * The process that calls CreateProcessWithTokenW must have the
		 * SE_IMPERSONATE_NAME privilege. If this function fails with
		 * ERROR_PRIVILEGE_NOT_HELD (1314), use the CreateProcessAsUser or
		 * CreateProcessWithLogonW function instead. Typically, the process that calls
		 * CreateProcessAsUser must have the SE_INCREASE_QUOTA_NAME privilege and may
		 * require the SE_ASSIGNPRIMARYTOKEN_NAME privilege if the token is not
		 * assignable. CreateProcessWithLogonW requires no special privileges, but the
		 * specified user account must be allowed to log on interactively. Generally, it
		 * is best to use CreateProcessWithLogonW to create a process with alternate
		 * credentials.
		 *
		 * @param hToken               A handle to the primary token that represents a
		 *                             user.
		 * @param dwLogonFlags         The logon option.. For a list of values, see
		 *                             Logon Flags.
		 * @param lpApplicationName    The name of the module to be executed.
		 * @param lpCommandLine        The command line to be executed.
		 * @param dwCreationFlags      The flags that control the priority class and the
		 *                             creation of the process. For a list of values,
		 *                             see Process Creation Flags.
		 * @param lpEnvironment        A pointer to an environment block for the new
		 *                             process. If this parameter is NULL, the new
		 *                             process uses the environment of the calling
		 *                             process.
		 *
		 *                             An environment block consists of a
		 *                             null-terminated block of null-terminated strings.
		 *                             Each string is in the following form:
		 *                             name=value\0
		 * @param lpCurrentDirectory   The full path to the current directory for the
		 *                             process. The string can also specify a UNC path.
		 * @param lpStartupInfo        A pointer to a STARTUPINFO or STARTUPINFOEX
		 *                             structure.
		 * @param lpProcessInformation A pointer to a PROCESS_INFORMATION structure that
		 *                             receives identification information about the new
		 *                             process.
		 * @return If the function succeeds, the return value is nonzero. If the
		 *         function fails, the return value is zero. To get extended error
		 *         information, call GetLastError.
		 */
		public boolean CreateProcessWithTokenW(HANDLE hToken, int dwLogonFlags, String lpApplicationName,
				String lpCommandLine, int dwCreationFlags, String lpEnvironment, String lpCurrentDirectory,
				STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInformation);

		boolean ConvertStringSecurityDescriptorToSecurityDescriptor(String sddl, int sddlVersion,
				PointerByReference psd, IntByReference length);

		/**
		 * Creates a new process and its primary thread. Then the new process runs the
		 * specified executable file in the security context of the specified
		 * credentials (user, domain, and password). It can optionally load the user
		 * profile for a specified user.
		 * 
		 * This function is similar to the CreateProcessAsUser and
		 * CreateProcessWithTokenW functions, except that the caller does not need to
		 * call the LogonUser function to authenticate the user and get a token.
		 * 
		 * @param lpUsername
		 * 
		 *                           The name of the user. This is the name of the user
		 *                           account to log on to. If you use the UPN format,
		 *                           user@DNS_domain_name, the lpDomain parameter must
		 *                           be NULL.
		 * 
		 *                           The user account must have the Log On Locally
		 *                           permission on the local computer. This permission
		 *                           is granted to all users on workstations and
		 *                           servers, but only to administrators on domain
		 *                           controllers.
		 * 
		 * @param lpDomain           The name of the domain or server whose account
		 *                           database contains the lpUsername account. If this
		 *                           parameter is NULL, the user name must be specified
		 *                           in UPN format.
		 * @param lpPassword
		 * 
		 *                           The clear-text password for the lpUsername account.
		 * 
		 * @param dwLogonFlags       The logon option. This parameter can be 0 (zero) or
		 *                           one of the following values.
		 * 
		 *                           LOGON_WITH_PROFILE 0x00000001
		 * 
		 * 
		 *                           Log on, then load the user profile in the
		 *                           HKEY_USERS registry key. The function returns after
		 *                           the profile is loaded. Loading the profile can be
		 *                           time-consuming, so it is best to use this value
		 *                           only if you must access the information in the
		 *                           HKEY_CURRENT_USER registry key.
		 * 
		 *                           Windows Server 2003: The profile is unloaded after
		 *                           the new process is terminated, whether or not it
		 *                           has created child processes.
		 * 
		 *                           Windows XP: The profile is unloaded after the new
		 *                           process and all child processes it has created are
		 *                           terminated.
		 * 
		 *                           LOGON_NETCREDENTIALS_ONLY 0x00000002
		 * 
		 * 
		 *                           Log on, but use the specified credentials on the
		 *                           network only. The new process uses the same token
		 *                           as the caller, but the system creates a new logon
		 *                           session within LSA, and the process uses the
		 *                           specified credentials as the default credentials.
		 * 
		 *                           This value can be used to create a process that
		 *                           uses a different set of credentials locally than it
		 *                           does remotely. This is useful in inter-domain
		 *                           scenarios where there is no trust relationship.
		 * 
		 *                           The system does not validate the specified
		 *                           credentials. Therefore, the process can start, but
		 *                           it may not have access to network resources.
		 * @param lpApplicationName
		 * 
		 *                           The name of the module to be executed. This module
		 *                           can be a Windows-based application. It can be some
		 *                           other type of module (for example, MS-DOS or OS/2)
		 *                           if the appropriate subsystem is available on the
		 *                           local computer.
		 * 
		 *                           The string can specify the full path and file name
		 *                           of the module to execute or it can specify a
		 *                           partial name. If it is a partial name, the function
		 *                           uses the current drive and current directory to
		 *                           complete the specification. The function does not
		 *                           use the search path. This parameter must include
		 *                           the file name extension; no default extension is
		 *                           assumed.
		 * 
		 *                           The lpApplicationName parameter can be NULL, and
		 *                           the module name must be the first white
		 *                           space–delimited token in the lpCommandLine string.
		 *                           If you are using a long file name that contains a
		 *                           space, use quoted strings to indicate where the
		 *                           file name ends and the arguments begin; otherwise,
		 *                           the file name is ambiguous.
		 * 
		 *                           For example, the following string can be
		 *                           interpreted in different ways:
		 * 
		 *                           "c:\program files\sub dir\program name"
		 * 
		 *                           The system tries to interpret the possibilities in
		 *                           the following order:
		 * 
		 *                           c:\program.exe files\sub dir\program name
		 *                           c:\program files\sub.exe dir\program name
		 *                           c:\program files\sub dir\program.exe name
		 *                           c:\program files\sub dir\program name.exe
		 * 
		 *                           If the executable module is a 16-bit application,
		 *                           lpApplicationName should be NULL, and the string
		 *                           pointed to by lpCommandLine should specify the
		 *                           executable module and its arguments.
		 * 
		 * @param lpCommandLine
		 * 
		 *                           The command line to be executed. The maximum length
		 *                           of this string is 1024 characters. If
		 *                           lpApplicationName is NULL, the module name portion
		 *                           of lpCommandLine is limited to MAX_PATH characters.
		 * 
		 *                           The function can modify the contents of this
		 *                           string. Therefore, this parameter cannot be a
		 *                           pointer to read-only memory (such as a const
		 *                           variable or a literal string). If this parameter is
		 *                           a constant string, the function may cause an access
		 *                           violation.
		 * 
		 *                           The lpCommandLine parameter can be NULL, and the
		 *                           function uses the string pointed to by
		 *                           lpApplicationName as the command line.
		 * 
		 *                           If both lpApplicationName and lpCommandLine are
		 *                           non-NULL, *lpApplicationName specifies the module
		 *                           to execute, and *lpCommandLine specifies the
		 *                           command line. The new process can use
		 *                           GetCommandLine to retrieve the entire command line.
		 *                           Console processes written in C can use the argc and
		 *                           argv arguments to parse the command line. Because
		 *                           argv[0] is the module name, C programmers typically
		 *                           repeat the module name as the first token in the
		 *                           command line.
		 * 
		 *                           If lpApplicationName is NULL, the first white
		 *                           space–delimited token of the command line specifies
		 *                           the module name. If you are using a long file name
		 *                           that contains a space, use quoted strings to
		 *                           indicate where the file name ends and the arguments
		 *                           begin (see the explanation for the
		 *                           lpApplicationName parameter). If the file name does
		 *                           not contain an extension, .exe is appended.
		 *                           Therefore, if the file name extension is .com, this
		 *                           parameter must include the .com extension. If the
		 *                           file name ends in a period with no extension, or if
		 *                           the file name contains a path, .exe is not
		 *                           appended. If the file name does not contain a
		 *                           directory path, the system searches for the
		 *                           executable file in the following sequence:
		 * 
		 *                           The directory from which the application loaded.
		 *                           The current directory for the parent process. The
		 *                           32-bit Windows system directory. Use the
		 *                           GetSystemDirectory function to get the path of this
		 *                           directory. The 16-bit Windows system directory.
		 *                           There is no function that obtains the path of this
		 *                           directory, but it is searched. The Windows
		 *                           directory. Use the GetWindowsDirectory function to
		 *                           get the path of this directory. The directories
		 *                           that are listed in the PATH environment variable.
		 *                           Note that this function does not search the
		 *                           per-application path specified by the App Paths
		 *                           registry key. To include this per-application path
		 *                           in the search sequence, use the ShellExecute
		 *                           function.
		 * 
		 *                           The system adds a null character to the command
		 *                           line string to separate the file name from the
		 *                           arguments. This divides the original string into
		 *                           two strings for internal processing.
		 * 
		 * @param dwCreationFlags    he flags that control how the process is created.
		 *                           The CREATE_DEFAULT_ERROR_MODE, CREATE_NEW_CONSOLE,
		 *                           and CREATE_NEW_PROCESS_GROUP flags are enabled by
		 *                           default— even if you do not set the flag, the
		 *                           system functions as if it were set. You can specify
		 *                           additional flags as noted. Value Meaning
		 * 
		 *                           CREATE_DEFAULT_ERROR_MODE 0x04000000
		 * 
		 * 
		 * 
		 *                           The new process does not inherit the error mode of
		 *                           the calling process. Instead,
		 *                           CreateProcessWithLogonW gives the new process the
		 *                           current default error mode. An application sets the
		 *                           current default error mode by calling SetErrorMode.
		 * 
		 *                           This flag is enabled by default.
		 * 
		 *                           CREATE_NEW_CONSOLE 0x00000010
		 * 
		 * 
		 * 
		 *                           The new process has a new console, instead of
		 *                           inheriting the parent's console. This flag cannot
		 *                           be used with the DETACHED_PROCESS flag.
		 * 
		 *                           This flag is enabled by default.
		 * 
		 *                           CREATE_NEW_PROCESS_GROUP 0x00000200
		 * 
		 * 
		 * 
		 *                           The new process is the root process of a new
		 *                           process group. The process group includes all
		 *                           processes that are descendants of this root
		 *                           process. The process identifier of the new process
		 *                           group is the same as the process identifier, which
		 *                           is returned in the lpProcessInfo parameter. Process
		 *                           groups are used by the GenerateConsoleCtrlEvent
		 *                           function to enable sending a CTRL+C or CTRL+BREAK
		 *                           signal to a group of console processes.
		 * 
		 *                           This flag is enabled by default.
		 * 
		 *                           CREATE_SEPARATE_WOW_VDM 0x00000800
		 * 
		 * 
		 * 
		 *                           This flag is only valid starting a 16-bit
		 *                           Windows-based application. If set, the new process
		 *                           runs in a private Virtual DOS Machine (VDM). By
		 *                           default, all 16-bit Windows-based applications run
		 *                           in a single, shared VDM. The advantage of running
		 *                           separately is that a crash only terminates the
		 *                           single VDM; any other programs running in distinct
		 *                           VDMs continue to function normally. Also, 16-bit
		 *                           Windows-based applications that run in separate
		 *                           VDMs have separate input queues, which means that
		 *                           if one application stops responding momentarily,
		 *                           applications in separate VDMs continue to receive
		 *                           input.
		 * 
		 *                           CREATE_SUSPENDED 0x00000004
		 * 
		 * 
		 * 
		 *                           The primary thread of the new process is created in
		 *                           a suspended state, and does not run until the
		 *                           ResumeThread function is called.
		 * 
		 *                           CREATE_UNICODE_ENVIRONMENT 0x00000400
		 * 
		 * 
		 * 
		 *                           Indicates the format of the lpEnvironment
		 *                           parameter. If this flag is set, the environment
		 *                           block pointed to by lpEnvironment uses Unicode
		 *                           characters. Otherwise, the environment block uses
		 *                           ANSI characters.
		 * 
		 *                           EXTENDED_STARTUPINFO_PRESENT 0x00080000
		 * 
		 * 
		 * 
		 *                           The process is created with extended startup
		 *                           information; the lpStartupInfo parameter specifies
		 *                           a STARTUPINFOEX structure.
		 * 
		 *                           Windows Server 2003 and Windows XP: This value is
		 *                           not supported.
		 * 
		 * 
		 * 
		 *                           This parameter also controls the new process's
		 *                           priority class, which is used to determine the
		 *                           scheduling priorities of the process's threads. For
		 *                           a list of values, see GetPriorityClass. If none of
		 *                           the priority class flags is specified, the priority
		 *                           class defaults to NORMAL_PRIORITY_CLASS unless the
		 *                           priority class of the creating process is
		 *                           IDLE_PRIORITY_CLASS or BELOW_NORMAL_PRIORITY_CLASS.
		 *                           In this case, the child process receives the
		 *                           default priority class of the calling process.
		 * @param lpEnvironment
		 * 
		 *                           A pointer to an environment block for the new
		 *                           process. If this parameter is NULL, the new process
		 *                           uses an environment created from the profile of the
		 *                           user specified by lpUsername.
		 * 
		 *                           An environment block consists of a null-terminated
		 *                           block of null-terminated strings. Each string is in
		 *                           the following form:
		 * 
		 *                           name=value
		 * 
		 *                           Because the equal sign (=) is used as a separator,
		 *                           it must not be used in the name of an environment
		 *                           variable.
		 * 
		 *                           An environment block can contain Unicode or ANSI
		 *                           characters. If the environment block pointed to by
		 *                           lpEnvironment contains Unicode characters, ensure
		 *                           that dwCreationFlags includes
		 *                           CREATE_UNICODE_ENVIRONMENT. If this parameter is
		 *                           NULL and the environment block of the parent
		 *                           process contains Unicode characters, you must also
		 *                           ensure that dwCreationFlags includes
		 *                           CREATE_UNICODE_ENVIRONMENT.
		 * 
		 *                           An ANSI environment block is terminated by two 0
		 *                           (zero) bytes: one for the last string and one more
		 *                           to terminate the block. A Unicode environment block
		 *                           is terminated by four zero bytes: two for the last
		 *                           string and two more to terminate the block.
		 * 
		 *                           To retrieve a copy of the environment block for a
		 *                           specific user, use the CreateEnvironmentBlock
		 *                           function.
		 * 
		 * @param lpCurrentDirectory
		 * 
		 *                           The full path to the current directory for the
		 *                           process. The string can also specify a UNC path.
		 * 
		 *                           If this parameter is NULL, the new process has the
		 *                           same current drive and directory as the calling
		 *                           process. This feature is provided primarily for
		 *                           shells that need to start an application, and
		 *                           specify its initial drive and working directory.
		 * 
		 * @param lpStartupInfo      A pointer to a STARTUPINFO or STARTUPINFOEX
		 *                           structure. The application must add permission for
		 *                           the specified user account to the specified window
		 *                           station and desktop, even for WinSta0\Default.
		 * 
		 *                           If the lpDesktop member is NULL or an empty string,
		 *                           the new process inherits the desktop and window
		 *                           station of its parent process. The application must
		 *                           add permission for the specified user account to
		 *                           the inherited window station and desktop.
		 * 
		 *                           Windows XP: CreateProcessWithLogonW adds permission
		 *                           for the specified user account to the inherited
		 *                           window station and desktop.
		 * 
		 *                           Handles in STARTUPINFO or STARTUPINFOEX must be
		 *                           closed with CloseHandle when they are no longer
		 *                           needed. Important If the dwFlags member of the
		 *                           STARTUPINFO structure specifies
		 *                           STARTF_USESTDHANDLES, the standard handle fields
		 *                           are copied unchanged to the child process without
		 *                           validation. The caller is responsible for ensuring
		 *                           that these fields contain valid handle values.
		 *                           Incorrect values can cause the child process to
		 *                           misbehave or crash. Use the Application Verifier
		 *                           runtime verification tool to detect invalid
		 *                           handles.
		 * 
		 * @param lpProcessInfo
		 * 
		 *                           A pointer to a PROCESS_INFORMATION structure that
		 *                           receives identification information for the new
		 *                           process, including a handle to the process.
		 * 
		 *                           Handles in PROCESS_INFORMATION must be closed with
		 *                           the CloseHandle function when they are not needed.
		 * 
		 * @return If the function succeeds, the return value is nonzero.
		 * 
		 *         If the function fails, the return value is 0 (zero). To get extended
		 *         error information, call GetLastError.
		 * 
		 *         Note that the function returns before the process has finished
		 *         initialization. If a required DLL cannot be located or fails to
		 *         initialize, the process is terminated. To get the termination status
		 *         of a process, call GetExitCodeProcess.
		 */
		boolean CreateProcessWithLogonW(String lpUsername, String lpDomain, String lpPassword, int dwLogonFlags,
				String lpApplicationName, String lpCommandLine, int dwCreationFlags, Pointer lpEnvironment,
				String lpCurrentDirectory, STARTUPINFO lpStartupInfo, PROCESS_INFORMATION lpProcessInfo);

		SC_HANDLE OpenSCManagerW(String lpMachineName, String lpDatabaseName, DWORD dwDesiredAccess);

		boolean QueryServiceConfig(SC_HANDLE hService, QUERY_SERVICE_CONFIG lpServiceConfig, int cbBufSize,
				IntByReference pcbBytesNeeded);

		SERVICE_STATUS_HANDLE RegisterServiceCtrlHandler(String lpServiceName,
				com.sun.jna.platform.win32.Winsvc.Handler lpHandlerProc);
	}

	public interface XWinsvc extends Winsvc {

		@FieldOrder({ "lpServiceName", "lpDisplayName", "ServiceStatusProcess" })
		public static class ENUM_SERVICE_STATUS_PROCESS extends Structure {
			public Pointer lpServiceName;
			public Pointer lpDisplayName;
			public SERVICE_STATUS_PROCESS ServiceStatusProcess;

			public ENUM_SERVICE_STATUS_PROCESS() {
				super(W32APITypeMapper.DEFAULT);
			}

			public ENUM_SERVICE_STATUS_PROCESS(Pointer pointer) {
				super(pointer);
				read();
			}
		}

		@FieldOrder({ "fDelayedAutostart" })
		public class SERVICE_DELAYED_AUTO_START_INFO extends ChangeServiceConfig2Info {
			public static class ByReference extends SERVICE_DELAYED_AUTO_START_INFO implements Structure.ByReference {
			}

			public boolean fDelayedAutostart;
		}

		@FieldOrder({ "lpDescription" })
		public class SERVICE_DESCRIPTION extends ChangeServiceConfig2Info {
			public static class ByReference extends SERVICE_DESCRIPTION implements Structure.ByReference {
			}

			public String lpDescription;
		}

		@FieldOrder({ "dwServiceSidType" })
		public class SERVICE_SID_INFO extends ChangeServiceConfig2Info {
			public static class ByReference extends SERVICE_SID_INFO implements Structure.ByReference {
			}

			public DWORD dwServiceSidType;
		}

		public final static DWORD SERVICE_SID_TYPE_NONE = new DWORD(0x00000000);

		public final static DWORD SERVICE_SID_TYPE_RESTRICTED = new DWORD(0x00000003);

		public final static DWORD SERVICE_SID_TYPE_UNRESTRICTED = new DWORD(0x00000001);
	}

	public enum Status {
		STARTED, STARTING, STOPPED, STOPPING, PAUSING, PAUSED, UNPAUSING, UNKNOWN;

		public boolean isRunning() {
			return this == STARTED || this == STARTING || this == PAUSED || this == PAUSING || this == PAUSED;
		}
	}

	public final class Win32Service {

		private String nativeName;
		private Status status = null;

		public Win32Service(String nativeName) {
			this(nativeName, null);
		}

		public Win32Service(String nativeName, Status status) {
			super();
			this.nativeName = nativeName;
			this.status = status;
		}

		public void configure(WindowsSystemServices service) {
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			Win32Service other = (Win32Service) obj;
			if (nativeName == null) {
				if (other.nativeName != null)
					return false;
			} else if (!nativeName.equals(other.nativeName))
				return false;
			return true;
		}

		public void uninstall() throws IOException {
			var advapi32 = XAdvapi32.INSTANCE;
			SC_HANDLE serviceManager, service;
			serviceManager = getManager(null, WinNT.GENERIC_ALL);
			try {
				service = advapi32.OpenService(serviceManager, nativeName, WinNT.GENERIC_ALL);
				if (service != null) {
					try {
						if (!advapi32.DeleteService(service)) {
							var err = Kernel32.INSTANCE.GetLastError();
							throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s",
									nativeName, err, Kernel32Util.formatMessageFromLastErrorCode(err)));
						}
					} finally {
						advapi32.CloseServiceHandle(service);
					}
				} else {
					var err = Kernel32.INSTANCE.GetLastError();
					throw new IOException(String.format("Failed to find service to uninstall '%s'. %d. %s", nativeName,
							err, Kernel32Util.formatMessageFromLastErrorCode(err)));
				}
			} finally {
				advapi32.CloseServiceHandle(serviceManager);
			}
		}

		public void start() throws IOException {
			synchronized (smgr) {
				smgr.open(WinNT.GENERIC_ALL);
				try {
					W32Service srv = smgr.openService(getNativeName(), WinNT.GENERIC_ALL);
					try {
						srv.waitForNonPendingState();
						if (srv.queryStatus().dwCurrentState == Winsvc.SERVICE_RUNNING) {
							return;
						}
						if (!Advapi32.INSTANCE.StartService(srv.getHandle(), 0, null)) {
							throw new Win32Exception(Kernel32.INSTANCE.GetLastError());
						}
						timedWaitForNonPendingState(srv, START_WAIT_TIME);
						if (srv.queryStatus().dwCurrentState != Winsvc.SERVICE_RUNNING) {
							throw new RuntimeException("Unable to start the service " + getNativeName());
						}
					} finally {
						srv.close();
					}
				} finally {
					smgr.close();
				}
			}
		}

		public void stop() throws IOException {
			synchronized (smgr) {
				smgr.open(Winsvc.SC_MANAGER_ALL_ACCESS);
				try {
					W32Service srv = smgr.openService(getNativeName(),
							Winsvc.SERVICE_STOP | Winsvc.SERVICE_QUERY_STATUS | Winsvc.SERVICE_ENUMERATE_DEPENDENTS);
					try {
						srv.stopService(STOP_WAIT_TIME);
					} finally {
						srv.close();
					}
				} finally {
					smgr.close();
				}
			}
		}

		public String getNativeName() {
			return nativeName;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((nativeName == null) ? 0 : nativeName.hashCode());
			return result;
		}

		public void setNativeName(String nativeName) {
			this.nativeName = nativeName;
		}

		@Override
		public String toString() {
			return "AbstractService [nativeName=" + getNativeName() + ", status=" + getStatus() + "]";
		}

		public Status getStatus() {
			synchronized (smgr) {
				var status = calcStatus();
				this.status = status;
				return status;
			}
		}

		protected Status calcStatus() {
			smgr.open(WinNT.GENERIC_READ);
			try {
				W32Service srv = smgr.openService(getNativeName(), WinNT.GENERIC_READ);
				try {
					SERVICE_STATUS_PROCESS q = srv.queryStatus();

					if (q.dwCurrentState == Winsvc.SERVICE_RUNNING)
						return Status.STARTED;
					else if (q.dwCurrentState == Winsvc.SERVICE_START_PENDING)
						return Status.STARTING;
					else if (q.dwCurrentState == Winsvc.SERVICE_PAUSE_PENDING)
						return Status.PAUSING;
					else if (q.dwCurrentState == Winsvc.SERVICE_PAUSED)
						return Status.PAUSED;
					else if (q.dwCurrentState == Winsvc.SERVICE_CONTINUE_PENDING)
						return Status.UNPAUSING;
					else if (q.dwCurrentState == Winsvc.SERVICE_STOP_PENDING)
						return Status.STOPPING;
					else if (q.dwCurrentState == Winsvc.SERVICE_STOPPED)
						return Status.STOPPED;
					else
						return Status.UNKNOWN;
				} finally {
					srv.close();
				}
			} catch (Win32Exception ew) {
				return Status.UNKNOWN;
			} finally {
				smgr.close();
			}
		}

		Status cachedStatus() {
			return status;
		}
	}

	final static Logger LOG = LoggerFactory.getLogger(WindowsSystemServices.class);

	private static final int MAX_WAIT_TIME = Integer
			.parseInt(System.getProperty("forker.win32.maxServiceWaitTime", "60000"));

	private static final long START_WAIT_TIME = Integer
			.parseInt(System.getProperty("forker.win32.startWaitTime", "15000"));

	private static final long STOP_WAIT_TIME = Integer
			.parseInt(System.getProperty("forker.win32.stopWaitTime", "30000"));

	public WindowsSystemServices() {
		smgr = new W32ServiceManager();
	}

	public static SC_HANDLE getManager(String machine, int access) {
		SC_HANDLE handle = Advapi32.INSTANCE.OpenSCManager(machine, null, access);
		if (handle == null) {
			int err = Native.getLastError();
			if (err == 5)
				throw new IllegalStateException("Access denied. Check credentials");
			else
				throw new IllegalStateException(String.format("Failed OpenSCManager: %s", Integer.toHexString(err)));
		}
		return (handle);
	}

	private W32ServiceManager smgr;
	private ScheduledFuture<?> task;

	@Override
	public void close() throws IOException {
		if (task != null)
			task.cancel(false);
	}

	public Win32Service getService(String name) throws IOException {
		load();
		for (var s : getServices()) {
			if (s.getNativeName().equals(name)) {
				return s;
			}
		}
		return null;
	}

	public List<? extends Win32Service> getServices() throws IOException {
		return load();
	}

	public boolean hasService(String name) throws IOException {
		return getService(name) != null;
	}

	/**
	 * do not wait longer than the wait hint. A good interval is one-tenth the wait
	 * hint, but no less than 1 second and no more than MAX_WAIT_TIME seconds.
	 */
	int sanitizeWaitTime(int dwWaitHint) {
		int dwWaitTime = dwWaitHint / 10;

		if (dwWaitTime < 1000) {
			dwWaitTime = 1000;
		} else if (dwWaitTime > MAX_WAIT_TIME) {
			dwWaitTime = MAX_WAIT_TIME;
		}
		return dwWaitTime;
	}

	void timedWaitForNonPendingState(W32Service srv, long timeout) {

		SERVICE_STATUS_PROCESS status = srv.queryStatus();
		status.dwWaitHint = (int) timeout;

		int previousCheckPoint = status.dwCheckPoint;
		int checkpointStartTickCount = Kernel32.INSTANCE.GetTickCount();

		while (isPendingState(status.dwCurrentState)) {

			// if the checkpoint advanced, start new tick count
			if (status.dwCheckPoint != previousCheckPoint) {
				previousCheckPoint = status.dwCheckPoint;
				checkpointStartTickCount = Kernel32.INSTANCE.GetTickCount();
			}

			// if the time that passed is greater than the wait hint - throw timeout
			// exception
			if (Kernel32.INSTANCE.GetTickCount() - checkpointStartTickCount > status.dwWaitHint) {
				throw new RuntimeException("Timeout waiting for service to change to a non-pending state.");
			}

			int dwWaitTime = sanitizeWaitTime(status.dwWaitHint);

			try {
				Thread.sleep(dwWaitTime);
			} catch (InterruptedException e) {
				throw new RuntimeException(e);
			}

			status = srv.queryStatus();
			status.dwWaitHint = (int) timeout;
		}
	}

	private boolean isPendingState(int state) {
		switch (state) {
		case Winsvc.SERVICE_CONTINUE_PENDING:
		case Winsvc.SERVICE_STOP_PENDING:
		case Winsvc.SERVICE_PAUSE_PENDING:
		case Winsvc.SERVICE_START_PENDING:
			return true;
		default:
			return false;
		}
	}

	private List<Win32Service> load() {
		synchronized (smgr) {
			try {
				smgr.open(Winsvc.SC_MANAGER_ALL_ACCESS);
				return Arrays
						.asList(smgr.enumServicesStatusExProcess(WinNT.SERVICE_WIN32, Winsvc.SERVICE_STATE_ALL, null))
						.stream().map(s -> new Win32Service(s.lpServiceName)).collect(Collectors.toList());
			} finally {
				smgr.close();
			}
		}
	}

}
