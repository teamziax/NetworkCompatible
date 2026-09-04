plugins { id("com.gradleup.nmcp") }
description = "Provider registration and Warden control client"
java { toolchain { languageVersion.set(JavaLanguageVersion.of(21)) } }
dependencies {
    api(libs.gson)
    implementation(project(":transport-nethernet"))
    testImplementation(libs.bundles.junit)
    testImplementation(project(":transport-raknet"))
    testRuntimeOnly(libs.junit.platform.launcher)
    testRuntimeOnly("dev.ziax.warden:libdatachannel-java:${rootProject.property("wardenNativeVersion")}:x86_64")
}
tasks.jar { manifest.attributes["Automatic-Module-Name"] = "org.cloudburstmc.netty.warden" }


tasks.test { useJUnitPlatform { excludeTags("native") } }
tasks.register("nativeBenchClasspath") {
    dependsOn(tasks.testClasses)
    doLast { println(sourceSets.test.get().runtimeClasspath.asPath) }
}
tasks.register<Test>("nativeAdmissionTest") {
    description = "Real fixed-UDP stateless host integration against the pinned JNI library"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) })
    useJUnitPlatform { includeTags("native") }
    maxParallelForks = 1
    testLogging { showStandardStreams = true }
}
