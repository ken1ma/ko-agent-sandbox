// The acceptance test's row "packageBin across dependsOn" runs in this project. sbt resolves a dependency between
// projects through Ivy, and Ivy first takes its lock file in the Ivy home (run-on-host-internals.md, "sbt", which also
// says when this fixture retires). The row measures the redirected Ivy home, not the proxy, so the build has two
// projects, one dependency between them and no external dependency.
lazy val core = project
lazy val app = project.dependsOn(core)
