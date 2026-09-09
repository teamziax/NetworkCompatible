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

`transport-nethernet` provides NetherNet transport and local HTTP signalling.
`external-signalling` lets a host register with its chosen provider and check
client connection tokens locally. Read the
[NXS v1 specification](docs/external-signalling/README.md) and the
[contribution history and proposed upstream PRs](docs/contribution-provenance.md).

Build the pinned native development chain with `bash scripts/bootstrap-native-admission.sh`,
then run `./gradlew --max-workers=2 build :external-signalling:nativeAdmissionTest`.
An existing local Maven repository can be selected with
`-PnativeMavenRepository=/absolute/path/to/maven`. The development native artifacts
currently target Linux x86_64 and system OpenSSL. Other platforms need their own
release builds and tests.

When editing documentation or PR descriptions, follow the
[technical-writing checklist](docs/technical-writing.md).
