# Network

### Introduction

Network components used within Cloudburst projects.

### Components

- [`netty-transport-raknet`](transport-raknet/README.md) - A RakNet implementation based on Netty patterns

### Maven

##### Repository:

For releases, use Maven Central.
Snapshots can be found in the repository below.

<details open>
<summary>Gradle (Kotlin DSL)</summary>

```kotlin
repositories {
    maven("https://repo.opencollab.dev/maven-snapshots/")
}
```

</details>
<details>
<summary>Gradle</summary>

```groovy
repositories {
    maven {
        url 'https://repo.opencollab.dev/maven-snapshots/'
    }
}
```

</details>
<details>
<summary>Maven</summary>

```xml

<repositories>
  <repository>
    <id>opencollab-snapshots</id>
    <url>https://repo.opencollab.dev/maven-snapshots/</url>
  </repository>
</repositories>
```

</details>


## NetherNet and external signalling

`transport-nethernet` provides the attributed NetherNet transport and local HTTP
signalling integration. `external-signalling` implements the open
[NetherNet External Signalling v1 contract](docs/external-signalling/README.md),
including registration, background lifecycle and stateless admission.
See [contribution provenance and intended submission slices](docs/contribution-provenance.md).

Build the pinned native development chain with `bash scripts/bootstrap-native-admission.sh`,
then run `./gradlew --max-workers=2 build :external-signalling:nativeAdmissionTest`.
An existing local Maven repository can be selected with
`-PnativeMavenRepository=/absolute/path/to/maven`. The development native artifacts
currently target Linux x86_64 and system OpenSSL; cross-platform release packaging
remains a separate release gate.
