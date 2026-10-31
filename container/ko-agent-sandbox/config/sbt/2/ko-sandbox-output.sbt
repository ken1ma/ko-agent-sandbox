// sbt writes the build output outside the workspace, for two reasons:
// - This repository's compile takes 604 s writing `target/out` through the ko-agent-fs filter, and 28 s writing
//   here (ko-agent-fs/fuse/doc/verification-log.md, "an sbt build").
// - Host and container builds stop sharing `target/out`. After a build-cache hit, host sbt 2 leaves its outputs
//   there as symlinks into the host's cache, class files included, and a compile here fails writing through them
//   (verification-log.md, "sbt over dangling cache links").
// The output directory is keyed by the build's absolute path, so two builds with one directory name do not share
// output.
// sbt has no system property for rootOutputDirectory. A global settings file is the one route that leaves the
// workspace's build alone.
rootOutputDirectory := {
  val buildRoot = (LocalRootProject / baseDirectory).value.getAbsolutePath.stripPrefix("/")
  (file(sys.props("user.home")) / ".cache" / "sbt-out").toPath.resolve(buildRoot)
}
