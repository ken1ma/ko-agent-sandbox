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

// The runtime image is distroless (`java -jar`, no shell), so the jar finds the Scala library through a manifest
// Class-Path, resolved relative to the jar's directory — which is why `dist` puts everything in one.
Compile / packageBin / packageOptions += {
  val converter = fileConverter.value

  Package.ManifestAttributes(
    "Class-Path" -> (Compile / dependencyClasspathAsJars).value
      .map(entry => converter.toPath(entry.data).getFileName.toString)
      .mkString(" "),
  )
}

// One directory for the Containerfile to copy, insulating it from sbt 2's target layout. The application jar gets the
// stable name the ENTRYPOINT uses; library jars keep the names the Class-Path references.
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
