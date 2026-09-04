name := "agent-egress-proxy"
version := "0.1.0"
scalaVersion := "3.8.4"

Compile / mainClass := Some("agentsandbox.egress.AgentEgressProxy")

libraryDependencies +=
  "org.scalameta" %% "munit" % "1.3.5" % Test

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-unchecked",
  "-Wunused:all",
  "-Werror",
)

// X509Helper mints leaves with the JDK's internal certificate builder, which the JVM keeps behind
// the module boundary at run time; scalac compiles against it unasked. The Containerfile passes the
// same two exports to native-image, and the launcher's manifest carries them for the host build's
// proxy.
Test / fork := true
Test / javaOptions ++= Seq(
  "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
)

// Native Image follows the jar's manifest Class-Path, resolved relative to the application jar. `dist` puts the
// application and every library jar in one directory so the container build needs no sbt-specific target paths.
Compile / packageBin / packageOptions += {
  val converter = fileConverter.value

  Package.ManifestAttributes(
    "Class-Path" -> (Compile / dependencyClasspathAsJars).value
      .map(entry => converter.toPath(entry.data).getFileName.toString)
      .mkString(" "),
  )
}

// One directory for Native Image, insulating the Containerfile from sbt 2's target layout. The application jar gets a
// stable name; library jars keep the names the Class-Path references.
lazy val dist = taskKey[Unit]("Assemble the runtime jars under target/dist")

dist := {
  val converter = fileConverter.value
  val directory = baseDirectory.value / "target" / "dist"

  IO.delete(directory)
  IO.createDirectory(directory)

  IO.copyFile(
    converter.toPath((Compile / packageBin).value).toFile,
    directory / "agent-egress-proxy.jar",
  )

  IO.copy(
    (Compile / dependencyClasspathAsJars).value
      .map(entry => converter.toPath(entry.data).toFile)
      .map(jar => jar -> directory / jar.getName),
  )

  streams.value.log.info(s"dist assembled in $directory")
}
