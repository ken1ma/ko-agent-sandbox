// Tests --cache-overlay against real sessions: what a session does through the overlay never reaches the host cache,
// whichever way the session ends, and concurrent sessions share only the host cache, never each other's writes.
//
// The suite runs only under testWithPodman, like the other container-launching suites (WithPodman has the
// condition):
//
//     sbt "testWithPodman *CacheOverlayLifecycleTest"
//
// The host cache is a temporary directory beside the scratch workspace, never the developer's own Coursier cache.

package agentsandbox.launcher

import java.nio.file.{Files, LinkOption, Path}
import java.nio.ByteBuffer
import java.nio.file.attribute.{BasicFileAttributes, PosixFileAttributes, PosixFilePermissions}
import java.nio.file.attribute.UserDefinedFileAttributeView
import java.util.HexFormat
import scala.jdk.CollectionConverters.*
import scala.util.{Try, Using}

import FileHelper.deleteRecursively
import HostCommands.*
import Podman.*
import WithPodman.{*, given}

class CacheOverlayLifecycleTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  private val Target = CacheOverlay.Kind.Coursier.destination

  /** macOS refuses the option (CacheOverlay.MacRefusal), which CacheOverlayTest covers. */
  private def supportedHost(): Unit = assume(currentOs != Os.Mac, "macOS refuses --cache-overlay")

  private val selinuxEnforcing =
    currentOs == Os.Linux &&
      findOnPath("getenforce", Os.Linux).exists(path => run(path.toString).text.trim == "Enforcing")

  /** Every entry under `root` with its type, size, modification time, mode, owner, group, extended attributes, SELinux
    * label and content: what SECURITY.md, "Cache overlay", says a session cannot change. */
  private def snapshot(root: Path): Map[String, String] =
    // GNU find fails where SELinux supplies no label, so the labels are read only where selinuxfs is mounted.
    val selinuxfs = currentOs == Os.Linux &&
      Files.readAllLines(Path.of("/proc/self/mounts")).asScala.exists(_.split(' ').lift(2).contains("selinuxfs"))
    val labels =
      if !selinuxfs then Map.empty[String, String]
      else
        val found = run("find", root.toString, "-printf", "%P %Z\n")
        assert(found.ok, s"find could not read the labels: ${found.err}")
        found.text.linesIterator.map(_.split(" ", 2)).collect { case Array(path, label) => path -> label }.toMap
    Using.resource(Files.walk(root)): entries =>
      entries.iterator.asScala.map: entry =>
        val relative = root.relativize(entry).toString
        val attributes = Files.readAttributes(entry, classOf[BasicFileAttributes], LinkOption.NOFOLLOW_LINKS)
        val posix = Try(Files.readAttributes(entry, classOf[PosixFileAttributes], LinkOption.NOFOLLOW_LINKS)).toOption
        val mode = posix.map(attributes => PosixFilePermissions.toString(attributes.permissions))
        val owner = Try(Files.getOwner(entry, LinkOption.NOFOLLOW_LINKS).getName).toOption
        val group = posix.map(_.group.getName)
        val extended = Try:
          val view = Files.getFileAttributeView(entry, classOf[UserDefinedFileAttributeView], LinkOption.NOFOLLOW_LINKS)
          view.list.asScala.sorted.map: name =>
            val value = ByteBuffer.allocate(view.size(name))
            view.read(name, value)
            s"$name=${HexFormat.of.formatHex(value.array)}"
        .toOption
        val content = if attributes.isRegularFile then Files.readString(entry) else ""
        val described =
          s"${attributes.isDirectory} ${attributes.size} ${attributes.lastModifiedTime} $mode $owner $group " +
            s"$extended ${labels.getOrElse(relative, "")}"
        relative -> s"$described $content"
      .toMap

  /** A host cache holding a marker and a fixture artifact, and the scratch workspace beside it. */
  private def withCache(body: (Path, Path) => Unit): Unit =
    val cache = Files.createTempDirectory("cache-overlay-lower").toRealPath()
    val workspace = scratchWorkspace()
    try
      Files.writeString(cache.resolve("marker"), "lower\n")
      Files.createDirectories(cache.resolve("https/repo1.maven.org"))
      Files.writeString(cache.resolve("https/repo1.maven.org/artifact.jar"), "fixture\n")
      // The launcher refuses a cache that an enforcing host keeps from containers, and never relabels one.
      if selinuxEnforcing then
        val labeled = run("chcon", "-R", "-t", "container_file_t", "-l", "s0", cache.toString)
        assert(labeled.ok, s"could not label $cache for containers: ${labeled.err}")
      body(cache, workspace)
    finally
      discard(workspace)
      deleteRecursively(cache)

  private def overlay(cache: Path): Vector[String] =
    Vector("--egress=deny-unless-allowed", s"${CacheOverlay.OptionName}=coursier=$cache")

  /** The volumes mounted into the session's container, such as its home and the workspace's persistent volume. The
    * checks below read these names alone, so a container of another program does not change their outcome.
    * - The template quotes `volume` with Go's backticks: Java passes a double quote in an argument unescaped on
    *   Windows (LauncherImages, the label template). */
  private def sessionVolumes(session: Session): Vector[String] =
    inspect(session.container, "{{range .Mounts}}{{if eq .Type `volume`}}{{.Name}} {{end}}{{end}}")
      .split(' ').filter(_.nonEmpty).toVector

  /** The anonymous volumes among `volumes`, which end with their container. A named one, such as the workspace's
    * persistent volume, lasts until --reset. Read while the session runs, since the volumes go with it. */
  private def anonymous(volumes: Vector[String]): Vector[String] =
    volumes.filter(name => inspect(name, "{{.Anonymous}}") == "true")

  /** Asserts that none of `volumes` exists any more. podman removes a container's anonymous volumes as the container
    * goes, which can lag the launcher's exit. */
  private def gone(volumes: Vector[String], after: String): Unit =
    polling.withMaxRetries(30).eventually:
      volumes.foreach: name =>
        val answer = LauncherState.existsAnswer(run(podman, "volume", "exists", name).exit)
        assertEquals(answer, Some(false), s"$after left the volume $name")

  /** Creates, replaces, renames and deletes through the overlay, and checks that the session sees its own writes. A new
    * file in an existing lower directory is how Coursier adds a version. The script stops at its first failing step,
    * and a failure shows what the session sees of the paths it wrote. */
  private def writeThrough(session: Session): Unit =
    val wrote = execSh(
      session,
      """set -e; d="$1"; echo created > "$d/created"; echo added > "$d/https/repo1.maven.org/added.jar"
        |echo replaced > "$d/https/repo1.maven.org/artifact.jar"
        |mv "$d/marker" "$d/renamed"; rm "$d/renamed"; mkdir "$d/directory"
        |cat "$d/created" "$d/https/repo1.maven.org/added.jar" "$d/https/repo1.maven.org/artifact.jar"; ls "$d"
        |""".stripMargin,
      Target,
    )
    def seen = execSh(
      session,
      """d="$1"; id; ls -lnd "$d" "$d/https" "$d/https/repo1.maven.org"; ls -ln "$d" "$d/https/repo1.maven.org"""",
      Target,
    )
    def written = s"stdout:\n${wrote.text}\nstderr:\n${wrote.err}\nwhat the session sees:\n${seen.text}\n${seen.err}"
    assert(wrote.ok, s"the session could not write through the overlay\n$written")
    assertEquals(
      wrote.text.linesIterator.toVector, Vector("created", "added", "replaced", "created", "directory", "https"),
      written,
    )

  test("a session reads the host cache, and its writes leave the host unchanged on a stop, a forced rm and --reset"):
    supportedHost()
    requireTestWithPodman()
    withCache: (cache, workspace) =>
      val before = snapshot(cache)

      val stopped = launchWith(workspace, workspace.resolve("stopped.log"), overlay(cache))
      val stoppedVolumes = sessionVolumes(stopped)
      val stoppedAnonymous = anonymous(stoppedVolumes)
      assert(stopped.output.contains(s"cache overlay: coursier"), stopped.output)
      val read = execSh(stopped, """cat "$1/marker" "$1/https/repo1.maven.org/artifact.jar"""", Target)
      assertEquals(read.text.linesIterator.toVector, Vector("lower", "fixture"), read.err)
      // The mount at v1 leaves its parent the session's, so Coursier can add the arc and jvm directories beside it.
      val parent = s"${SandboxWorkspace.ContainerHome}/.cache/coursier"
      val siblings = execSh(stopped, """stat -c %u:%g "$1" && mkdir "$1/arc" "$1/jvm"""", parent)
      assert(siblings.ok, s"the session could not add arc and jvm beside the overlay: ${siblings.err}")
      assertEquals(siblings.text.trim, "65532:65532", s"$parent is not the session's")
      writeThrough(stopped)
      stop(stopped)
      assertEquals(snapshot(cache), before, "a stopped session changed the host cache")
      gone(stoppedAnonymous, "a stopped session")

      val removed = launchWith(workspace, workspace.resolve("removed.log"), overlay(cache))
      val removedVolumes = sessionVolumes(removed)
      val removedAnonymous = anonymous(removedVolumes)
      writeThrough(removed)
      // --volumes, as the launcher's own removals pass it: without it podman keeps the anonymous home volume, which
      // exists with or without the overlay.
      val forced = run(podman, "rm", "--force", "--volumes", "--time", "0", removed.container)
      assert(forced.ok, s"could not remove ${removed.container}: ${forced.err}")
      removed.launcher.waitFor(Patience, java.util.concurrent.TimeUnit.SECONDS): Unit
      assertEquals(snapshot(cache), before, "a forcibly removed session changed the host cache")
      gone(removedAnonymous, "a forced removal")

      // --reset ends a live session, and the upper layer goes with the session's container.
      val live = launchWith(workspace, workspace.resolve("live.log"), overlay(cache))
      val liveVolumes = sessionVolumes(live)
      writeThrough(live)
      val (ok, output) = reset(workspace)
      assert(ok, s"--reset failed; its output:\n$output")
      val remains = run(podman, "container", "exists", live.container)
      assertEquals(LauncherState.existsAnswer(remains.exit), Some(false), s"--reset left ${live.container}:\n$output")
      live.launcher.waitFor(Patience, java.util.concurrent.TimeUnit.SECONDS): Unit
      assertEquals(snapshot(cache), before, "--reset changed the host cache")
      // Every volume a session mounted is gone, the persistent volume after --reset alone.
      gone(stoppedVolumes ++ removedVolumes ++ liveVolumes, "--reset")

  test("concurrent sessions share the host cache and never see each other's writes"):
    supportedHost()
    requireTestWithPodman()
    withCache: (cache, workspace) =>
      val before = snapshot(cache)
      val first = launchWith(workspace, workspace.resolve("first.log"), overlay(cache))
      val second = launchWith(workspace, workspace.resolve("second.log"), overlay(cache))
      try
        assert(execSh(first, """echo first > "$1/first"""", Target).ok)
        assert(execSh(second, """echo second > "$1/second"""", Target).ok)
        def listing(session: Session): Vector[String] =
          execSh(session, """ls "$1"""", Target).text.linesIterator.toVector
        assertEquals(listing(first), Vector("first", "https", "marker"))
        assertEquals(listing(second), Vector("https", "marker", "second"))
        assertEquals(snapshot(cache), before, "a running session's write reached the host cache")
      finally
        stop(first)
        stop(second)

  test("without the option, the host cache is invisible and the session's own cache dies with the session"):
    supportedHost()
    requireTestWithPodman()
    withCache: (_, workspace) =>
      val options = Vector("--egress=deny-unless-allowed")
      val session = launchWith(workspace, workspace.resolve("plain.log"), options)
      val listed = execSh(session, """mkdir -p "$1" && echo session > "$1/session" && ls "$1"""", Target)
      assertEquals(listed.text.linesIterator.toVector, Vector("session"), listed.err)
      stop(session)
      val next = launchWith(workspace, workspace.resolve("next.log"), options)
      try assertEquals(execSh(next, """ls -A "$1" 2>/dev/null""", Target).text, "")
      finally stop(next)
