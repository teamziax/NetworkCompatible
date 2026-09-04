plugins { id("com.gradleup.nmcp") }
description = "Provider registration and Warden control client"
version = providers.gradleProperty("wardenVersion").getOrElse("0.1.0-registration-dev")
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    api(libs.gson)
    testImplementation(libs.bundles.junit)
    testRuntimeOnly(libs.junit.platform.launcher)
}
tasks.jar { manifest.attributes["Automatic-Module-Name"] = "org.cloudburstmc.netty.warden" }

tasks.register<JavaExec>("providerStub") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("org.cloudburstmc.netty.warden.IndependentProviderStub")
}

tasks.register<JavaExec>("providerBench") {
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass.set("org.cloudburstmc.netty.warden.WardenProviderBench")
    listOf("providerOrigin", "providerState", "providerMode", "providerGrantFile", "providerHoldSeconds").forEach { name ->
        providers.gradleProperty(name).orNull?.let { systemProperty(name, it) }
    }
}

// Avoid shell-specific dependency-cache paths in the cross-repository local workflow.
tasks.register("providerBenchClasspath") {
    dependsOn(tasks.testClasses)
    doLast { println(sourceSets.test.get().runtimeClasspath.asPath) }
}
