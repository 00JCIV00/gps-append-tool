import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.7.10"
    application
}

group = "00JCIV00"
version = "0.0.5a"

repositories {
    mavenCentral()
}

dependencies {
    // Kotlin Standard
    testImplementation(kotlin("test"))

    // Local
    fileTree("/lib").filter { file -> file.name.endsWith(".jar") }
                            .forEach { jar ->
                                implementation(files(jar))
                                println("Implemented local jar: ${jar.name}")
                            }

    // External
    implementation("com.github.ajalt.clikt:clikt:3.+")
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

tasks.register("updateVersionNumbers") {
    println("Updating Version Numbers to $version...")
    var updatedVer = false
    var updList = mutableListOf("README.md")
    fileTree("/src").forEach {file ->
        if (file.isFile && file.name.contains(".kt")) updList.add(file.absolutePath)
    }
    updList.forEach { fileName ->
        val nextFile = File(fileName)
        val newLines: MutableList<String> = mutableListOf()
        var updateFile = false
        nextFile.useLines { lines ->
            lines.forEachIndexed { _, line ->
                // RegEx for version type
                val verRegex = Regex("\\d\\.\\d\\.\\d[a-z]?")
                val newLine = if (line.contains("Version:") && line.contains(regex = verRegex) && verRegex.find(line)?.range?.let {line.substring(it)} != version) {
                    println("..Updated '${fileName}'")
                    updatedVer = true
                    updateFile = true
                    line.replace(verRegex, version.toString())
                } else line
                newLines.add(newLine)
            }
        }
        if(updateFile) {
            nextFile.printWriter().use { out ->
                newLines.forEach { line ->
                    out.println(line)
                }
            }
        }
    }
    if(updatedVer)
        println("Updated Version Numbers to $version.")
    else
        println("No Version Numbers to Update.")
}

tasks.startScripts {
    applicationName = "gat"
}

tasks.assembleDist {
    dependsOn("updateVersionNumbers")
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    dependsOn("updateVersionNumbers")
    kotlinOptions.jvmTarget = "11"
}

tasks.jar {
    dependsOn("updateVersionNumbers")
    duplicatesStrategy = DuplicatesStrategy.INCLUDE

    manifest {
        attributes["Main-Class"] = "MainKt"
    }

    configurations["compileClasspath"].forEach { file: File ->
        from(zipTree(file.absoluteFile))
    }
}

tasks.build {
    dependsOn("updateVersionNumbers")
}