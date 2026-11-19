// Each sbt build in a live workspace gets a container volume over its project/target, so that the host's sbt and the
// session's do not replace each other's server address file, project/target/active.json. Only that directory is
// hidden; target/ stays shared. doc/limitations.md, "sbt in a build made during a session", has the failure and the
// builds this leaves out.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.{FileAlreadyExistsException, FileVisitResult, Files, LinkOption, Path, SimpleFileVisitor}
import scala.jdk.CollectionConverters.*

import HostCommands.Os

object SbtBuildVolumes:

  /** Directories the walk does not enter: no build that sbt is started in lives there, and they can be large. */
  private val Pruned = Set(".git", ".ko-agent-sandbox", "node_modules", "target")

  /**
   * The characters that Windows allows a whole command line, its terminator included (CreateProcessW). The volumes
   * that would push `podman create` past it are left out (fitting).
   */
  val WindowsCommandLineLimit = 32767

  /**
   * The builds found before the start prompt: `targets` are the `project/target` directories to give a volume, which
   * may not exist yet, and `skipped` are the builds that get none, each with the reason.
   */
  final case class Planned(targets: Vector[Target], skipped: Vector[(Path, String)])

  /** A `project/target` directory to give a volume, and the real paths of its build directory and of the workspace
    * root when `plan` read them. */
  final case class Target(target: Path, realRoot: Path, realWorkspace: Path)

  /**
   * The directories under `workspaceRoot` that hold an sbt build: `build.sbt` or `project/build.properties`, shallow
   * ones first.
   * - The `project` directory of such a build holds that build's definition, not a build that sbt is started in.
   * - `src/sbt-test` holds an sbt plugin's scripted tests, each a build that scripted copies elsewhere before running
   *   it, and is not entered. sbt's own repository holds hundreds of them
   *   (https://www.scala-sbt.org/1.x/docs/Testing-sbt-plugins.html).
   * - The walk enters neither a symlink nor a junction. Java reports a Windows junction as a directory, not as a
   *   symlink.
   */
  def buildRoots(workspaceRoot: Path): Vector[Path] =
    val found = Vector.newBuilder[Path]
    Files.walkFileTree(
      workspaceRoot,
      new SimpleFileVisitor[Path]:
        override def preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult =
          val name = Option(dir.getFileName).map(_.toString).getOrElse("")
          val scripted = name == "sbt-test" && Option(dir.getParent).flatMap(p => Option(p.getFileName))
            .exists(_.toString == "src")
          if dir != workspaceRoot && (attrs.isOther || scripted || Pruned.contains(name)) then
            FileVisitResult.SKIP_SUBTREE
          else
            val definition = dir != workspaceRoot && name == "project" && holdsBuild(dir.getParent)
            if !definition && holdsBuild(dir) then found += dir
            FileVisitResult.CONTINUE

        override def visitFileFailed(file: Path, ex: IOException): FileVisitResult = FileVisitResult.CONTINUE
    )
    found.result().sortBy(root => (root.getNameCount, root.toString))

  /**
   * The builds to give a volume, read without writing anything. A build is skipped:
   * - when its `project` or `project/target` is anything but a plain directory: podman would resolve a symlink there
   *   and mount the volume over whatever it names;
   * - when the last of `ruleLines` that names its `project`, its `project/target` or an ancestor is `read-only`, so
   *   that the launch neither creates a directory there nor hides what is there. The guard's own additions, a hook
   *   directory or a listed symlink's target, are not consulted yet (doc/TODO.md, "The guard's read-only paths in the
   *   sbt build volumes"): they hold hooks and agent configuration rather than builds.
   * mountPathOf refuses a `:`, which a `--volume` value cannot carry.
   */
  def plan(workspaceRoot: Path, ruleLines: Vector[FileRules.Line], os: Os): Planned =
    val realWorkspace = workspaceRoot.toRealPath()
    val (targets, skipped) = buildRoots(workspaceRoot).partitionMap: root =>
      val project = root.resolve("project")
      val target = project.resolve("target")
      def skip(reason: String) = Right((root, reason))
      def components(path: Path) = workspaceRoot.relativize(path).iterator.asScala.map(_.toString).toVector
      if Vector(project, target).exists(path => Files.exists(path, LinkOption.NOFOLLOW_LINKS) && !plainDirectory(path))
      then skip("its project or project/target is not a plain directory")
      else if Vector(project, target).exists(path => FileRules.readOnlyByLines(components(path), ruleLines)) then
        skip("a read-only file rule covers its project or project/target")
      else if SandboxWorkspace.mountPathOf(os, target).isLeft then skip("its path holds a `:`")
      else
        try
          // The real path must be the walked one, so that the rules checked above apply where prepare creates.
          val realRoot = root.toRealPath()
          if realRoot == realWorkspace.resolve(workspaceRoot.relativize(root)) then
            Left(Target(target, realRoot, realWorkspace))
          else skip("its real path is not the path the walk found")
        catch case ex: IOException => skip(s"reading the build directory failed: ${ex.getMessage}")
    Planned(targets, skipped)

  /**
   * After the start prompt, creates each target's missing `project` and `project/target` on the host, as sbt does at
   * its first run, so that the mount point exists before podman mounts the volume there. Returns the container paths
   * to mount at, and the builds that changed since `plan` read them.
   * - A build directory that no longer holds a build, or whose real path changed or lies outside the workspace, as
   *   when an ancestor became a symlink, is skipped and nothing is created in it.
   * - Each directory is created alone, which never follows a symlink at its own name, and is read again afterwards.
   * - A change between those reads and the creation or podman's mount still redirects them: java.nio has no
   *   directory-relative `mkdir` to pin the parents (doc/TODO.md, "Deferred — the sbt build volumes' host creation,
   *   pinned to the checked directories"). The creation then lands wherever the changed path leads, and the mount
   *   stays inside the container.
   */
  def prepare(planned: Planned, os: Os): (Vector[String], Vector[(Path, String)]) =
    planned.targets.partitionMap: planned =>
      val target = planned.target
      val project = target.getParent
      val root = project.getParent
      def changed(reason: String) = Right((root, reason))
      try
        if !holdsBuild(root) || root.toRealPath() != planned.realRoot
          || !planned.realRoot.startsWith(planned.realWorkspace) then
          changed("it no longer holds a build at the path the launch found")
        else
          Vector(project, target).foreach: dir =>
            try Files.createDirectory(dir)
            catch case _: FileAlreadyExistsException => ()
            if !plainDirectory(dir) then throw IOException(s"$dir is not a plain directory")
          SandboxWorkspace.mountPathOf(os, target).fold(_ => changed("its path holds a `:`"), Left(_))
      catch case ex: IOException => changed(s"preparing project/target failed: ${ex.getMessage}")

  /**
   * The mounts that fit `podman create` when `limit` caps its command line: `command` is the rest of that command
   * line, and the mounts keep their order. A word costs at most `windowsCost` on the command line, and 260
   * characters (Windows' MAX_PATH) stay free for the resolved executable that replaces the first word.
   */
  def fitting(command: Vector[String], mounts: Vector[String], limit: Option[Int]): Vector[String] =
    def cost(words: Vector[String]): Int = words.map(windowsCost).sum
    limit match
      case None => mounts
      case Some(max) =>
        val room = max - 1 - 260 - cost(command)
        val costs = mounts.map(mount => cost(arguments(Vector(mount))))
        mounts.zip(costs.scanLeft(0)(_ + _).tail).takeWhile((_, used) => used <= room).map(_(0))

  /**
   * An upper bound on the characters that Java's Windows argument encoding gives `word`: a separator, two quotes,
   * and one more character for each backslash or quote, since the encoding escapes a quote and doubles the
   * backslashes before a quote or the closing one (OpenJDK's windows ProcessImpl, createCommandLine).
   */
  def windowsCost(word: String): Int = word.length + 3 + word.count(ch => ch == '\\' || ch == '"')

  /**
   * The `podman create` words for the volumes. A `--volume` value of one field is an anonymous volume at that
   * destination, and only a `:` would split it (podman's pkg/specgen/volumes.go, GenVolumeMounts). Each is anonymous,
   * so `--rm` removes it with the container.
   */
  def arguments(mounts: Vector[String]): Vector[String] =
    mounts.flatMap(mount => Vector("--volume", mount))

  /** The launch's warning for builds without a volume, whose sbt servers the host and the container may share. */
  def skippedWarning(skipped: Vector[(Path, String)], os: Os): Option[String] =
    Option.when(skipped.nonEmpty):
      val lines = skipped.map((root, reason) => s"  ${HostCommands.pathInline(root, os)}: $reason")
      val heading = "sbt in the session shares project/target with the host in these builds, so a host sbt may then " +
        "need `sbt shutdownall` (doc/limitations.md, \"sbt in a build made during a session\"):"
      (heading +: lines).mkString("\n")

  private def holdsBuild(dir: Path): Boolean =
    regularFile(dir.resolve("build.sbt")) || regularFile(dir.resolve("project").resolve("build.properties"))

  private def regularFile(path: Path): Boolean = Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)

  private def plainDirectory(path: Path): Boolean =
    try
      val attrs = Files.readAttributes(path, classOf[BasicFileAttributes], LinkOption.NOFOLLOW_LINKS)
      attrs.isDirectory && !attrs.isOther
    catch case _: IOException => false
