// Build output outside the project, for two reasons. This repository's compile takes 604 s
// writing `target/out` through the ko-agent-fs filter and 28 s writing here
// (fuse/ko-agent-fs/doc/verification-log.md, "an sbt build"). And host and container builds stop
// sharing `target/out`: after a build-cache hit host sbt 2 leaves its outputs there, class files
// included, as symlinks into the host's cache, and a compile here fails writing through them
// (verification-log.md, "sbt over dangling cache links"). Keyed by the build's absolute path, so
// two builds with one directory name do not share output. sbt has no system property for
// rootOutputDirectory; a global settings file is the one route that leaves the project's build
// alone.
rootOutputDirectory := {
  val buildRoot = (LocalRootProject / baseDirectory).value.getAbsolutePath.stripPrefix("/")
  (file(sys.props("user.home")) / ".cache" / "sbt-out").toPath.resolve(buildRoot)
}
