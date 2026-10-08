# SolarSSH Server - Developers Guide

This document has information for developers of SolarSSH Server.

# Running tests

Run all the tests like this:

```sh
./gradlew clean check
```


# Release script

The `config/tools/release.sh` script can be used to update the project version and create a new
release tag. For example to release version `1.0.0`:

```sh
./config/tools/release 1.0.0
```

You can preview what the script does with a `-n` option:

```sh
RELEASE: DRY RUN: no changes will be made.
RELEASE: start release 1.0.0
RELEASE: Update gradle.properties version to 1.0.0
RELEASE: commit release version changes.
RELEASE: Update gradle.properties version to 1.0.1-dev.0
RELEASE: commit development version changes.
RELEASE: switch to main for publish.
```
