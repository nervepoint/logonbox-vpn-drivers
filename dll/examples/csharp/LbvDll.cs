using System;
using System.Runtime.InteropServices;

static class LbvDll
{

    /*
     * Create a new isolate, considering the passed parameters (which may be NULL).
     *
     * Returns 0 on success, or a non-zero value on failure.
     *
     * On success, the current thread is attached to the created isolate, and the
     * address of the isolate and the isolate thread are written to the passed pointers
     * if they are not NULL.
     */
    //int graal_create_isolate(graal_create_isolate_params_t* params, graal_isolate_t** isolate, graal_isolatethread_t** thread);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "graal_create_isolate")]
    public static extern int GraalCreateIsolate([In] in IntPtr parms, [Out] out IntPtr isolate, [Out] out IntPtr thread);

    /*
     * Tears down the isolate of the passed (and still attached) isolate thread,
     * waiting for any attached threads to detach from it, then discards its objects,
     * threads, and any other state or context that is associated with it.
     *
     * Returns 0 on success, or a non-zero value on failure.
     */        //int graal_tear_down_isolate(graal_isolatethread_t* isolateThread);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "graal_tear_down_isolate")]
    public static extern int GraalTearDownIsolate([In] in IntPtr thread);

    //long long int up(graal_isolatethread_t*, char*, long long int, long long int);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "up")]
    public static extern long Up([In] in IntPtr thread, IntPtr configFile, long systemconfHandle, long contextHandle);

    //int down(graal_isolatethread_t*, long long int);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "down")]
    public static extern int Down([In] in IntPtr thread, long vpnHandle);

    //int get_error_code(graal_isolatethread_t*);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "get_error_code")]
    public static extern int GetErrorCode([In] in IntPtr thread);

    //int set_configuration_search_path(graal_isolatethread_t*, char*);
    [DllImport("../../target/liblbv.so", SetLastError = false, EntryPoint = "set_configuration_search_path")]
    public static extern int SetConfigurationSearchPath([In] in IntPtr thread, IntPtr searchPath);
}
