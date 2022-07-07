import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.7.0"
    application
}

group = "org.jc__iv"
version = "0.0.1a"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("com.github.ajalt.clikt:clikt:3.5.0")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

application {
    mainClass.set("MainKt")
}

tasks.jar {
    duplicatesStrategy = org.gradle.api.file.DuplicatesStrategy.INCLUDE

    manifest {
        attributes["Main-Class"] = "MainKt"
    }

    configurations["compileClasspath"].forEach { file: File ->
        from(zipTree(file.absoluteFile))
    }
}