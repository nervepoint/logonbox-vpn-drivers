# dft-tcp

[Back To DFT](../README.md)

This module servers serves as a reference implementation and example for *DFT*. It may also
be a useful tool in its own right, allowing rapid file transfer between two hosts.

It uses a simple binary protocol over TCP. 

## Building 

You will need .. 

 * [Java 11 or later](https://adoptium.net/),
 * [Apache Maven](https://maven.apache.org/)

```
mvn clean package -P shaded
```

This will produce a "shaded" executable Jar `tcp/target/dft-tcp-[version]-launcher.jar`, which
contains both the send and receive tools.

## Usage



## Graal Native Image

The demonstration tools can also be built as two natively compiled command using Graal Native Image

Install the latest Graal SDK, set `GRAAL_VM_HOME` and `JAVA_HOME` to point to the SDK.

(if on Windows run inside a Visual Studio command prompt)

```
mvn clean package -P native-image
```

This will produce two executables in `target`, `dft-recv` and `dft-send`.

There are other profiles you can add for native images. `-P` expects a comma separated list
of profiles.

 | native-image | Enable native image generation (always required) |
 | instrument | Will instrument the generated executables so that when run they produce a `default.iprof` file. This may be fed back into a 2nd build using the `instrumented` profile. |
 | instrumented | Will use a `default.iprof` file to generate an optimised executable. |
 | compatibility | Will add `--march=compatibility` to generate the most compatible executable possible. Note this may have an impact on performance. |