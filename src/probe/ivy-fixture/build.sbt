// The gate's "packageBin across dependsOn" row: resolving an inter-project edge enters Ivy, which
// takes its lock file in the Ivy home first (run-on-host.md "sbt", which also says when this
// fixture retires). Two projects, one edge, no external dependency: the row measures the
// redirected Ivy home, not the proxy.
lazy val core = project
lazy val app = project.dependsOn(core)
