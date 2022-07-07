import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.7.0"
    application
}

group = "00JCIV00"
version = "0.0.2a"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("com.github.ajalt.clikt:clikt:3.5.0")
    //implementation ("com.ardikars.pcap:pcap:${PCAP-LATEST-VERSION}")
}

application {
    mainClass.set("MainKt")
}

distributions{
    main {
        contents {
            from("/") {
                include("README.md")
                into("docs")
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
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