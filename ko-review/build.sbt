name := "ko-review"
// The plugin's version, which the assembly writes into .claude-plugin/plugin.json and the jar's manifest. The review
// files carry a format version of their own (ReviewFiles.FormatVersion).
version := "0.2.0"
scalaVersion := "3.10.1"

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-unchecked",
  "-Wunused:all",
  "-Werror",
)

Compile / mainClass := Some("koreview.Main")

libraryDependencies ++= Seq(
  "io.circe" %% "circe-core" % "0.14.17",
  "io.circe" %% "circe-parser" % "0.14.17",
  "org.tomlj" % "tomlj" % "2.2.0",
  "org.scalameta" %% "munit" % "1.3.6" % Test,
)

// The plugin as Claude Code and Codex install it, under target/plugin/ko-review: plugin/ with claude-plugin/ renamed
// to .claude-plugin/, the helper's jar in lib/, and lib/dependencies.txt, which lists the dependencies that the
// runtime image fetches (plugin/README.md).
lazy val pluginAssembly = taskKey[File]("Assemble the plugin without its dependencies' jars")

pluginAssembly := Def.uncached {
  val converter = fileConverter.value
  val source = baseDirectory.value / "plugin"
  val target = baseDirectory.value / "target" / "plugin" / "ko-review"
  IO.delete(target)
  for
    file <- source.allPaths.get()
    if file.isFile && file.getName != ".DS_Store" && file.getName != "README.md"
    relative <- IO.relativize(source, file)
  do
    val renamed = relative.replace('\\', '/').replaceFirst("^claude-plugin/", ".claude-plugin/")
    IO.copyFile(file, target / renamed)
    if file.canExecute then (target / renamed).setExecutable(true, false)
  val manifest = target / ".claude-plugin" / "plugin.json"
  val text = IO.read(manifest)
  if !text.contains("\"name\": \"ko-review\",") then sys.error(s"$manifest must hold \"name\": \"ko-review\",")
  val named = "\"name\": \"ko-review\","
  IO.write(manifest, text.replace(named, s"$named\n  \"version\": \"${version.value}\","))
  IO.copyFile(converter.toPath((Compile / packageBin).value).toFile, target / "lib" / "ko-review.jar")
  val modules = update.value.configuration(Runtime.toConfigRef).toVector.flatMap(_.modules).filterNot(_.evicted)
    .map(report => s"${report.module.organization}:${report.module.name}:${report.module.revision}").distinct.sorted
  IO.write(target / "lib" / "dependencies.txt", modules.mkString("", "\n", "\n"))
  target
}

// The assembled plugin with its dependencies' jars, under target/dist/ko-review, for use outside the image.
lazy val dist = taskKey[Unit]("Assemble the plugin with its dependencies' jars under target/dist")

dist := Def.uncached {
  val converter = fileConverter.value
  val target = baseDirectory.value / "target" / "dist" / "ko-review"
  IO.delete(target)
  IO.copyDirectory(pluginAssembly.value, target, preserveExecutable = true)
  IO.copy((Runtime / externalDependencyClasspath).value.map(entry => converter.toPath(entry.data).toFile)
    .map(jar => jar -> target / "lib" / jar.getName))
  streams.value.log.info(s"dist: $target")
}

// The suites drive the helper in their own JVM. A turn makes that JVM Linux's child subreaper and kills every child it
// has once the reviewer ends, which must never happen to sbt's own JVM.
// - Under the run-on-host sandbox, Xcode's /usr/bin/git shim fails, so the suites run in a session container or on a
//   host outside the sandbox, as the egress proxy's do.
// - The forked JVM starts in this directory, where the suites read plugin/.
Test / fork := true
// - A turn kills every child of the JVM once the reviewer ends, so two suites' turns at once would kill each other's
//   reviewers.
Test / parallelExecution := false
// - The forked JVM's java.class.path does not hold the classes, which the suites' child JVMs need: the reviewer's
//   group joins through JoinGroup, and the fake reviewer runs as a JVM of its own.
Test / javaOptions ++= {
  val converter = fileConverter.value
  val classpath = (Test / fullClasspath).value.map(entry => converter.toPath(entry.data))
  Seq(
    "--enable-native-access=ALL-UNNAMED",
    s"-Dko-review.assembled-plugin=${pluginAssembly.value}",
    s"-Dko-review.test-classpath=${classpath.mkString(java.io.File.pathSeparator)}",
  )
}
