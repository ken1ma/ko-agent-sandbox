// The run-on-host suites' sbt fixture: the test rows run here. This repository's own tests bind TCP listeners, which
// the profile refuses an sbt command, so a test row in this repository fails whenever sbt reruns one of those tests.
// - The root project has one passing test class.
// - `failing` has one failing test class. The root does not aggregate it, so only `failing/testFull` runs it, for the
//   row that checks a failure's exit code.
ThisBuild / scalaVersion := "3.10.0"

val munit = "org.scalameta" %% "munit" % "1.3.6" % Test

lazy val root = (project in file(".")).settings(libraryDependencies += munit)

lazy val failing = project.settings(libraryDependencies += munit)
