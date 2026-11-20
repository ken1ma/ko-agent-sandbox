// Tests --cache-overlay: the option's spellings, where each kind finds its host cache on Linux and Windows, macOS's
// refusal, the directories a cache may not overlap, and the one volume argument a resolved cache adds. The
// container-launching suite CacheOverlayLifecycleTest proves what podman's `:O` does with the session's writes.

package agentsandbox.launcher

import java.nio.file.{Files, Path, Paths}
import java.nio.file.attribute.PosixFilePermissions

import CacheOverlay.*
import CommandLine.*
import FileHelper.deleteRecursively
import HostCommands.Os
import SandboxWorkspace.HomeProtection

class CacheOverlayTest extends munit.FunSuite:

  private def parsed(args: String*): Either[String, ParsedCommandLine] = parseCommandLine(args.toList)

  private val windowsJvm = HostCommands.currentOs == Os.Windows

  /** The tests that spell POSIX paths: a Windows JVM reads them as relative, and refuses a `:` in one. */
  private def posixPaths(): Unit = assume(!windowsJvm, "a Windows JVM does not read the test's POSIX paths as absolute")

  /** `posix` as an absolute path of the JVM's own: on drive C: under a Windows JVM. */
  private def native(posix: String): String = if windowsJvm then "C:" + posix.replace('/', '\\') else posix

  test("the option names a kind, alone or with an absolute directory split at the first '='"):
    assertEquals(parsed("--cache-overlay=coursier").map(_.cacheOverlays), Right(Vector(Request(Kind.Coursier, None))))
    val directory = native("/var/cache/coursier=a,b/v1")
    assertEquals(
      parsed(s"--cache-overlay=coursier=$directory").map(_.cacheOverlays),
      Right(Vector(Request(Kind.Coursier, Some(directory)))),
    )
    assertEquals(Request(Kind.Coursier, Some("/c/v1")).spelled, "--cache-overlay=coursier=/c/v1")

  test("an absent or unknown kind, an empty or relative directory, a repeated kind and a separated value refuse"):
    def refusal(args: String*): String = parsed(args*).swap.getOrElse(fail(s"${args.mkString(" ")} was accepted"))
    assert(refusal("--cache-overlay=ivy").contains("the kinds are coursier, exactly"))
    assert(refusal("--cache-overlay==/c/v1").contains("the kinds are coursier"))
    assert(refusal("--cache-overlay=coursier=").contains("name the cache's directory after '='"))
    assert(refusal("--cache-overlay=coursier=cache/v1").contains("must be an absolute path"))
    assert(refusal("--cache-overlay=coursier", s"--cache-overlay=coursier=${native("/c/v1")}").contains("given twice"))
    assert(refusal("--cache-overlay", "coursier").contains("--cache-overlay=<kind>[=<directory>]"))

  test("the empty value drops earlier entries, and after the command a same-spelled token is the command's"):
    assertEquals(parsed("--cache-overlay=coursier", "--cache-overlay=").map(_.cacheOverlays), Right(Vector.empty))
    val forwarded = parsed("bash", "--cache-overlay=coursier").fold(fail(_), identity)
    assertEquals((forwarded.command, forwarded.cacheOverlays), (List("bash", "--cache-overlay=coursier"), Vector.empty))
    val escaped = parsed("--", "--cache-overlay=coursier").fold(fail(_), identity)
    assertEquals((escaped.command, escaped.cacheOverlays), (List("--cache-overlay=coursier"), Vector.empty))

  test("a management action sees the option as a session option it reads not"):
    // launcherMain refuses every option among givenOptions that the action does not read.
    val withAction = parseArguments(List("--cache-overlay=coursier", "--build")).fold(fail(_), identity)
    assertEquals(withAction.action.map(_._1), Some("--build"))
    assertEquals(givenOptions(withAction), Vector(OptionName))
    Vector(AgentSandboxLauncher.ResetReads, AgentSandboxLauncher.EgressEffectiveReads).foreach: reads =>
      assert(!reads.contains(OptionName))

  test("COURSIER_CACHE names the cache exactly when set; an empty or relative value refuses"):
    def found(os: Os, env: (String, String)*): Either[String, Path] = coursierDownloadCache(os, env.toMap.get)
    val cache = native("/data/cs")
    assertEquals(found(Os.Linux, "COURSIER_CACHE" -> cache, "HOME" -> "/home/me"), Right(Paths.get(cache)))
    assertEquals(found(Os.Windows, "COURSIER_CACHE" -> native("/data/cs/")), Right(Paths.get(cache)))
    assert(found(Os.Linux, "COURSIER_CACHE" -> "", "HOME" -> "/home/me").swap.exists(_.contains("COURSIER_CACHE")))
    assert(found(Os.Linux, "COURSIER_CACHE" -> "cs", "HOME" -> "/home/me").swap.exists(_.contains("'cs'")))

  test("without COURSIER_CACHE, Linux finds v1 under XDG_CACHE_HOME, else under ~/.cache"):
    posixPaths()
    def found(os: Os, env: (String, String)*): Either[String, Path] = coursierDownloadCache(os, env.toMap.get)
    assertEquals(found(Os.Linux, "HOME" -> "/home/me"), Right(Paths.get("/home/me/.cache/coursier/v1")))
    assertEquals(found(Os.Linux, "HOME" -> "/home/me", "XDG_CACHE_HOME" -> "/x"), Right(Paths.get("/x/coursier/v1")))
    assert(found(Os.Linux).swap.exists(_.contains("HOME")))

  test("on Windows, the cache is v1 under LOCALAPPDATA's Coursier\\Cache"):
    def found(env: (String, String)*): Either[String, Path] = coursierDownloadCache(Os.Windows, env.toMap.get)
    val local = native("/Users/me/AppData/Local")
    assertEquals(found("LOCALAPPDATA" -> local), Right(Paths.get(local, "Coursier", "Cache", "v1")))
    assert(found("HOME" -> native("/Users/me")).swap.exists(_.contains("LOCALAPPDATA")))

  private val homes = HomeProtection(Seq(Paths.get("/home/me")), Seq(Paths.get("/home")), Seq.empty)
  private val workspace = Protected(Paths.get("/home/me/src/app"), "the workspace, which the session writes")
  private val state = Protected(Paths.get("/home/me/.local/state/ko-agent-sandbox"), "the launcher's state")
  private val storage = Protected(Paths.get("/home/me/.local/share/containers"), "podman's storage")

  /** A Linux mount table with the root mount alone, which every Linux check needs. */
  private val rootOnly = parseMountInfo("22 1 8:1 / / rw - ext4 /dev/sda1 rw")

  private def refused(cache: String, os: Os = Os.Linux): Option[String] =
    val mounts = if os == Os.Linux then rootOnly else Vector.empty
    refusal(Paths.get(cache), homes, Vector(workspace, state, storage), os, mounts)

  test("a filesystem root, a home or what holds one, and another user's home refuse"):
    posixPaths()
    assertEquals(refused("/"), Some("it is a filesystem root"))
    Vector("/home/me", "/home", "/home/other").foreach: cache =>
      assert(refused(cache).exists(_.contains("home directory")), cache)

  test("an overlap with a protected directory refuses in either direction, and a narrower cache passes"):
    posixPaths()
    assert(refused("/home/me/src/app/cache").exists(_.contains("the workspace")))
    assert(refused("/home/me/src").exists(_.contains("the workspace")))
    assert(refused("/home/me/.local/state").exists(_.contains("the launcher's state")))
    assert(refused("/home/me/.local/share/containers/storage").exists(_.contains("podman's storage")))
    assertEquals(refused("/home/me/.cache/coursier/v1"), None)
    // A cache outside the home passes the same checks.
    assertEquals(refused("/var/cache/coursier/v1"), None)

  test("on Linux, a bind mount that shows the cache within the workspace, or the workspace at the cache, refuses"):
    posixPaths()
    // Device 8:1 holds /, and two mounts show its directories again: the cache inside the workspace, and the workspace
    // at a path with a space, which the kernel spells \040.
    val mounts = parseMountInfo(
      Vector(
        "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
        "40 22 8:1 /home/me/.cache/coursier/v1 /home/me/src/app/cache rw,relatime - ext4 /dev/sda1 rw",
        "41 22 8:2 / /data rw,relatime - ext4 /dev/sdb1 rw",
        "42 22 8:1 /home/me/src/app /mnt/app\\040copy rw,relatime - ext4 /dev/sda1 rw",
      ).mkString("\n"),
    )
    assertEquals(mounts(3), Mount("42", "22", "8:1", Paths.get("/home/me/src/app"), Paths.get("/mnt/app copy")))
    def mounted(cache: String) = refusal(Paths.get(cache), homes, Vector(workspace, state, storage), Os.Linux, mounts)
    assert(mounted("/home/me/.cache/coursier/v1").exists(_.contains("a mount shows it")), "the bound cache")
    assert(mounted("/home/me/.cache/coursier").exists(_.contains("the workspace")), "what holds the bound cache")
    assert(mounted("/mnt/app copy/v1").exists(_.contains("the workspace")), "a cache in the workspace's second path")
    assertEquals(mounted("/home/me/.cache/other/v1"), None)
    assertEquals(mounted("/data/home/me/.cache/coursier/v1"), None, "another device's directory of the same name")

  test("on Linux, the mount that shows a path is found by parent ids, so a mount hidden by an overmount is skipped"):
    posixPaths()
    // 31 lies below /x on mount 30, and 32 overmounts /x with the workspace, which hides 31 though mountinfo lists it.
    val mounts = parseMountInfo(
      Vector(
        "22 1 8:1 / / rw - ext4 /dev/sda1 rw",
        "30 22 8:3 / /x rw - ext4 /dev/sdc1 rw",
        "31 30 8:4 / /x/y rw - ext4 /dev/sdd1 rw",
        "32 30 8:1 /home/me/src/app /x rw - ext4 /dev/sda1 rw",
      ).mkString("\n"),
    )
    val refused = refusal(Paths.get("/x/y/v1"), homes, Vector(workspace), Os.Linux, mounts)
    assert(refused.exists(_.contains("the workspace")), refused)

  test("on Linux, a mount that shows a home, or the directory of homes, at another path refuses as the home does"):
    posixPaths()
    val mounts = parseMountInfo(
      Vector("22 1 8:1 / / rw - ext4 /dev/sda1 rw", "23 22 8:1 /home /mnt/homes rw - ext4 /dev/sda1 rw")
        .mkString("\n"),
    )
    def mounted(cache: String) = refusal(Paths.get(cache), homes, Vector.empty, Os.Linux, mounts)
    Vector("/mnt/homes", "/mnt/homes/me", "/mnt/homes/other").foreach: cache =>
      assert(mounted(cache).exists(_.contains("a mount shows it as a home directory")), cache)
    assertEquals(mounted("/mnt/homes/me/.cache/coursier/v1"), None, "a cache inside a home passes, as without a mount")

  test("on Linux, a root mount that is its own parent is found, and a mount table without a root, or empty, refuses"):
    posixPaths()
    // The root lists itself as its parent; another user's home is a device of its own, bound again at /mnt/o.
    val mounts = parseMountInfo(
      Vector(
        "22 22 8:1 / / rw - ext4 /dev/sda1 rw",
        "24 22 8:5 / /home/other rw - ext4 /dev/sde1 rw",
        "25 22 8:5 / /mnt/o rw - ext4 /dev/sde1 rw",
        "40 22 8:1 /home/me/.cache/coursier/v1 /home/me/src/app/cache rw - ext4 /dev/sda1 rw",
      ).mkString("\n"),
    )
    def mounted(cache: String) = refusal(Paths.get(cache), homes, Vector(workspace), Os.Linux, mounts)
    assert(mounted("/home/me/.cache/coursier/v1").exists(_.contains("a mount shows it")), "the bound cache")
    assert(mounted("/mnt/o").exists(_.contains("as a home directory")), "another user's mounted home")
    assertEquals(mounted("/mnt/o/.cache/coursier/v1"), None, "a cache inside that home passes, as without a mount")
    val rootless = parseMountInfo("40 22 8:1 /home/me/.cache /mnt/c rw - ext4 /dev/sda1 rw")
    val noRoot = refusal(Paths.get("/var/cache/v1"), homes, Vector(workspace), Os.Linux, rootless)
    assert(noRoot.exists(_.contains("lists no root mount")), noRoot)
    val empty = refusal(Paths.get("/var/cache/v1"), homes, Vector(workspace), Os.Linux, Vector.empty)
    assert(empty.exists(_.contains("lists no root mount")), empty)

  test("a path podman cannot take as a --volume source, or whose ',' would split the overlay's options, refuses"):
    posixPaths()
    assert(refused("/var/cache/a:b").exists(_.contains("podman cannot mount it")))
    assert(refused("/var/cache/a,upperdir=x/v1").exists(_.contains("a path with a ','")))
    assert(refused("/var/cache/a\\b/v1").exists(_.contains("as an escape")))

  private def withDirectory(body: Path => Unit): Unit =
    val root = Files.createTempDirectory("cache-overlay").toRealPath()
    try body(root)
    finally deleteRecursively(root)

  private def resolved(
    request: Request,
    readable: Boolean = true,
    creatable: Boolean = true,
    env: Map[String, String] = Map.empty,
  ) =
    resolve(
      request, Os.Linux, env.get, homes, Vector(workspace, state, storage), _ => readable, _ => creatable, rootOnly,
    )

  test("resolve canonicalizes the directory, and refuses a missing one, a file, and one the session cannot use"):
    posixPaths()
    withDirectory: root =>
      val cache = Files.createDirectories(root.resolve("v1"))
      val link = Files.createSymbolicLink(root.resolve("link"), cache)
      assertEquals(resolved(Request(Kind.Coursier, Some(link.toString))), Right(Resolved(Kind.Coursier, cache)))
      val missing = resolved(Request(Kind.Coursier, Some(root.resolve("absent").toString)))
      assert(missing.swap.exists(_.contains("the launcher creates no cache")), missing)
      assert(missing.swap.exists(_.contains("--cache-overlay=coursier=<directory>")), missing)
      val file = Files.writeString(root.resolve("file"), "")
      assert(resolved(Request(Kind.Coursier, Some(file.toString))).swap.exists(_.contains("is a file")))
      // The suggested command quotes the path, so a pasted command relabels the cache alone.
      val spaced = Files.createDirectories(root.resolve("v 1"))
      val unreadable = resolved(Request(Kind.Coursier, Some(spaced.toString)), readable = false)
      assert(unreadable.swap.exists(_.contains(s"chcon -R -t container_file_t -l s0 '$spaced'")), unreadable)
      val uncreatable = resolved(Request(Kind.Coursier, Some(spaced.toString)), creatable = false)
      assert(uncreatable.swap.exists(_.contains(s"chmod u+wx '$spaced'")), uncreatable)
      // The bare kind follows COURSIER_CACHE.
      assertEquals(
        resolved(Request(Kind.Coursier, None), env = Map("COURSIER_CACHE" -> cache.toString)),
        Right(Resolved(Kind.Coursier, cache)),
      )

  test("the session can create a file in the upper root when the class that applies grants write and search"):
    def creatable(mode: String, uid: Int, gid: Int): Boolean = creatableBy(Integer.parseInt(mode, 8), uid, gid, 501, 20)
    assert(creatable("755", 501, 0))
    assert(creatable("300", 501, 0))
    assert(!creatable("600", 501, 0), "write without search creates nothing")
    assert(!creatable("577", 501, 20), "the owner class applies, even where the group and others may write")
    assert(creatable("575", 0, 20))
    assert(!creatable("757", 0, 20), "the group class applies, even where others may write")
    assert(creatable("757", 0, 0))
    assert(!creatable("775", 0, 0))

  test("the process's ids are read unsigned from /proc/self/status"):
    val status = Vector("Name:\tjava", "Uid:\t3000000000\t3000000000\t3000000000\t3000000000", "Gid:\t20\t20\t20\t20")
    assertEquals(statusId(status, "Uid"), Some(Integer.parseUnsignedInt("3000000000")))
    assertEquals(statusId(status, "Gid"), Some(20))
    assertEquals(statusId(status, "Groups"), None)

  test("on Linux, a cache root without write and search for the launching user is one the session cannot add to"):
    assume(HostCommands.currentOs == Os.Linux, "the check reads /proc/self/status")
    withDirectory: root =>
      val cache = Files.createDirectories(root.resolve("v1"))
      assert(sessionCanCreateOnLinux(cache))
      Files.setPosixFilePermissions(cache, PosixFilePermissions.fromString("rw-r--r--"))
      assert(!sessionCanCreateOnLinux(cache))
      Files.setPosixFilePermissions(cache, PosixFilePermissions.fromString("rwxr-xr-x"))

  test("macOS refuses the option before it looks for the cache"):
    val refused =
      resolve(
        Request(Kind.Coursier, None), Os.Mac, Map.empty.get, homes, Vector.empty, _ => true, _ => true, Vector.empty,
      )
    assertEquals(refused, Left(s"error: --cache-overlay=coursier; $MacRefusal"))

  test("COURSIER_CACHE keeps its spelling until the file system resolves it, as the explicit directory does"):
    posixPaths()
    withDirectory: root =>
      // The link's `..` leads to sub, the link target's parent; dropping `link/..` as text would lead to root.
      Files.createDirectories(root.resolve("sub/inner"))
      val physical = Files.createDirectories(root.resolve("sub/v1"))
      Files.createDirectories(root.resolve("v1"))
      Files.createSymbolicLink(root.resolve("link"), root.resolve("sub/inner"))
      val spelled = s"$root/link/../v1"
      assertEquals(resolved(Request(Kind.Coursier, Some(spelled))), Right(Resolved(Kind.Coursier, physical)))
      assertEquals(
        resolved(Request(Kind.Coursier, None), env = Map("COURSIER_CACHE" -> spelled)),
        Right(Resolved(Kind.Coursier, physical)),
      )

  test("podman's storage roots are read from its JSON, a trailing space included"):
    posixPaths()
    assertEquals(
      AgentSandboxLauncher.podmanStorageRoots("""{"graphRoot":"/g ","runRoot":"/r","volumePath":"/g /volumes"}"""),
      Right(Vector(Paths.get("/g "), Paths.get("/r"), Paths.get("/g /volumes"))),
    )
    assert(AgentSandboxLauncher.podmanStorageRoots("""{"graphRoot":"/g","runRoot":""}""").isLeft)
    assert(AgentSandboxLauncher.podmanStorageRoots("not json").isLeft)

  test("a resolved cache adds one --volume ending in :O at the kind's fixed destination"):
    posixPaths()
    assertEquals(
      Resolved(Kind.Coursier, Paths.get("/home/me/.cache/coursier/v1")).volumeArg,
      "--volume=/home/me/.cache/coursier/v1:/home/nonroot/.cache/coursier/v1:O",
    )
