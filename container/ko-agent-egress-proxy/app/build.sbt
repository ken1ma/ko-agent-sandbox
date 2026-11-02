name := "ko-agent-egress-proxy"
version := "0.1.0"
scalaVersion := "3.10.0"

Compile / mainClass := Some("agentsandbox.egress.AgentEgressProxy")

libraryDependencies +=
  "org.scalameta" %% "munit" % "1.3.6" % Test

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-unchecked",
  "-Wunused:all",
  "-Werror",
)

// X509Helper issues leaves with the JDK's internal certificate builder. scalac compiles against the builder unasked,
// but the JVM keeps the builder behind the module boundary at run time, so the forked tests need these two exports.
// - The launcher carries the same two exports for the runner and the supervisor, which issue each host proxy's
//   certificates (RunOnHostSandbox.CertificateBuilderExports).
// - The image's native-image takes neither export, because nothing the proxy runs reaches X509Helper. Measured with
//   GraalVM 25.3.4.1, the image reaches the same types, fields and methods with and without the exports.
Test / fork := true
Test / javaOptions ++= Seq(
  "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
)

// Native Image follows the jar's manifest Class-Path and resolves its entries relative to the application jar.
// `dist` puts the application jar and every library jar in one directory, so the container build needs no
// sbt-specific target paths.
Compile / packageBin / packageOptions += {
  val converter = fileConverter.value

  Package.ManifestAttributes(
    "Class-Path" -> (Compile / dependencyClasspathAsJars).value
      .map(entry => converter.toPath(entry.data).getFileName.toString)
      .mkString(" "),
  )
}

// `dist` gives Native Image one directory, which keeps sbt 2's target layout out of the Containerfile. The
// application jar gets a stable name, and the library jars keep the names that the Class-Path references.
lazy val dist = taskKey[Unit]("Assemble the runtime jars under target/dist")

dist := {
  val converter = fileConverter.value
  val directory = baseDirectory.value / "target" / "dist"

  IO.delete(directory)
  IO.createDirectory(directory)

  IO.copyFile(
    converter.toPath((Compile / packageBin).value).toFile,
    directory / "ko-agent-egress-proxy.jar",
  )

  IO.copy(
    (Compile / dependencyClasspathAsJars).value
      .map(entry => converter.toPath(entry.data).toFile)
      .map(jar => jar -> directory / jar.getName),
  )

  streams.value.log.info(s"dist assembled in $directory")
}
