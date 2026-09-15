// sandbox-apt-get's unpack loop, run as the shell script it is: what a package upgrade leaves in
// $HOME/.local/deb and the wrappers beside it. apt is stubbed — the archives placed in the cache
// stand in for what it would download — so the test exercises the unpack, not the fetch.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import java.nio.file.attribute.PosixFilePermissions

import scala.jdk.CollectionConverters.*
import scala.util.Using

class SandboxAptGetTest extends munit.FunSuite:

  private val script = Path.of("container/ko-agent-sandbox/sandbox-apt-get").toAbsolutePath
  private val sh = Path.of("/bin/sh")

  // dpkg builds and lists the archives; the script runs only in the Debian image, and so does this
  // suite's host there. A host without them — a developer's macOS or Fedora — skips.
  private def tooling: Boolean =
    Files.isExecutable(sh) && Vector("dpkg-deb", "dpkg", "tar").forall(onPath)
  private def onPath(program: String): Boolean =
    sys.env.getOrElse("PATH", "").split(":").exists(dir => Files.isExecutable(Path.of(dir, program)))

  private def executable(path: Path, body: String): Unit =
    Files.writeString(path, body)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))

  /** A .deb of `pkg` at `version` holding the given paths, each a script printing its package and
    * version; those under usr/bin are the commands the script wraps. */
  private def buildDeb(into: Path, pkg: String, version: String, paths: String*): Path =
    val stage = Files.createDirectories(into.resolve(s"stage-$pkg-$version"))
    Files.createDirectories(stage.resolve("DEBIAN"))
    Files.writeString(
      stage.resolve("DEBIAN/control"),
      s"""Package: $pkg
         |Version: $version
         |Architecture: all
         |Maintainer: fixture <fixture@example.invalid>
         |Description: sandbox-apt-get fixture
         |""".stripMargin,
    )
    paths.foreach: path =>
      val file = stage.resolve(path)
      Files.createDirectories(file.getParent)
      executable(file, s"#!/bin/sh\necho $pkg ${file.getFileName} $version\n")
    val deb = into.resolve(s"${pkg}_${version}_all.deb")
    val build = ProcessBuilder("dpkg-deb", "--build", "--root-owner-group", stage.toString, deb.toString)
      .redirectOutput(ProcessBuilder.Redirect.DISCARD)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start()
    assertEquals(build.waitFor(), 0, s"dpkg-deb built $pkg $version")
    deb

  private def run(program: Path): String =
    val process = ProcessBuilder(program.toString).redirectErrorStream(true).start()
    val out = String(process.getInputStream.readAllBytes())
    process.waitFor()
    out

  private def deleteRecursively(path: Path): Unit =
    Using.resource(Files.walk(path)): entries =>
      entries.iterator().asScala.toVector.reverse.foreach(Files.deleteIfExists)

  /**
   * A HOME with the package lists an install requires, a cache to place archives in, and the
   * script bound to them. apt is not on the path: the stub's `update` seeds the list, its
   * `install` downloads nothing.
   */
  private final class Fixture(root: Path):
    val home: Path = Files.createDirectories(root.resolve("home"))
    private val debs = Files.createDirectories(root.resolve("debs"))
    val usrBin: Path = home.resolve(".local/deb/usr/bin")
    val localBin: Path = Files.createDirectories(home.resolve(".local/bin"))
    private val stubBin = Files.createDirectories(root.resolve("stub"))
    executable(
      stubBin.resolve("apt-get"),
      """#!/bin/sh
        |lists=
        |for a in "$@"; do case "$a" in Dir::State::Lists=*) lists=${a#*=} ;; esac; done
        |for a in "$@"; do case "$a" in
        |  update) mkdir -p "$lists"; : > "$lists/deb_Packages"; exit 0 ;;
        |  install) echo "1 newly installed"; exit 0 ;;
        |esac; done
        |exit 0
        |""".stripMargin,
    )
    assertEquals(sandboxAptGet("update"), 0)
    private val cache = Files.createDirectories(home.resolve(".local/deb/apt/cache/archives"))

    def sandboxAptGet(args: String*): Int =
      val builder = ProcessBuilder((sh.toString +: script.toString +: args)*)
        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
      builder.environment().put("HOME", home.toString)
      builder.environment().put("PATH", s"$stubBin:${sys.env.getOrElse("PATH", "")}")
      builder.start().waitFor()

    /** Places the archive in the cache as apt would have after a download. */
    def place(pkg: String, version: String, paths: String*): Unit =
      val deb = buildDeb(debs, pkg, version, paths*)
      Files.copy(deb, cache.resolve(deb.getFileName))
      ()

    def install(pkg: String, version: String, paths: String*): Unit =
      place(pkg, version, paths*)
      assertEquals(sandboxAptGet("install", pkg), 0, s"install $pkg $version")

  private def fixture(check: Fixture => Unit): Unit =
    assume(tooling, "runs sandbox-apt-get under /bin/sh with dpkg and tar")
    val root = Files.createTempDirectory("sandbox-apt-get")
    try check(Fixture(root))
    finally deleteRecursively(root)

  test("an upgrade removes files the superseded version owned and the wrappers for its commands"):
    fixture: f =>
      f.install("demo", "1.9", "usr/bin/common", "usr/bin/old-only")
      assert(Files.exists(f.usrBin.resolve("old-only")), "1.9 shipped old-only")
      assert(Files.exists(f.localBin.resolve("old-only")), "old-only was wrapped")

      // 1.10 arrives beside 1.9 in the cache, as a mid-session `update` then `install` leaves it.
      // 1.10 precedes 1.9 by filename, so only a version compare picks it as the newer.
      f.install("demo", "1.10", "usr/bin/common")
      assert(!Files.exists(f.usrBin.resolve("old-only")), "the upgrade removed old-only")
      assert(!Files.exists(f.localBin.resolve("old-only")), "the upgrade swept old-only's wrapper")
      assert(Files.exists(f.localBin.resolve("common")), "common stays wrapped")
      assertEquals(run(f.usrBin.resolve("common")), "demo common 1.10\n", "common is the newer version")

      // A re-run with the same cache extracts nothing new and fails nothing.
      assertEquals(f.sandboxAptGet("install", "demo"), 0)
      assert(!Files.exists(f.usrBin.resolve("old-only")), "the re-run kept old-only gone")

  test("a file that moved to another package survives the upgrade that stopped shipping it"):
    fixture: f =>
      f.install("demo", "1.0", "usr/bin/moved")
      // The upgrade and the package taking the file over arrive in one download; `demo-data`
      // precedes `demo_2.0` by filename, so its copy is extracted before demo's cleanup runs.
      f.place("demo-data", "1.0", "usr/bin/moved")
      f.place("demo", "2.0")
      assertEquals(f.sandboxAptGet("install", "demo"), 0)
      assertEquals(run(f.usrBin.resolve("moved")), "demo-data moved 1.0\n", "demo-data's copy stays")
      assert(Files.exists(f.localBin.resolve("moved")), "and so does its wrapper")
      assertEquals(f.sandboxAptGet("install", "demo"), 0)
      assert(Files.exists(f.usrBin.resolve("moved")), "the re-run leaves the file alone")

  test("a deletion the upgrade could not make is retried, not recorded as done"):
    fixture: f =>
      val obsolete = f.home.resolve(".local/deb/usr/share/demo")
      f.install("demo", "1.9", "usr/bin/common", "usr/share/demo/old-only")
      // The obsolete file's directory refuses the deletion; 1.10 ships nothing under it, so the
      // extraction itself succeeds and only the cleanup fails.
      Files.setPosixFilePermissions(obsolete, PosixFilePermissions.fromString("r-xr-xr-x"))
      assume(!Files.isWritable(obsolete), "a directory this user cannot write to; root can")
      try
        f.place("demo", "1.10", "usr/bin/common")
        assertNotEquals(f.sandboxAptGet("install", "demo"), 0, "the refused deletion fails the install")
        assert(Files.exists(obsolete.resolve("old-only")), "old-only is still there")
      finally Files.setPosixFilePermissions(obsolete, PosixFilePermissions.fromString("rwxr-xr-x"))
      assertEquals(f.sandboxAptGet("install", "demo"), 0, "the retry")
      assert(!Files.exists(obsolete.resolve("old-only")), "the retry removed old-only")
      assert(!Files.exists(f.home.resolve(".local/deb/.unpacked/demo.new")), "the manifest is committed")
