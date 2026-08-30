// What a host build is allowed to touch, decided before any of it runs: where this project's
// disposable build caches live, which JDK and launcher are the Coursier-managed ones, and which
// directory a request from inside the sandbox may name as a working directory. PLAN-SBT-ON-HOST.md
// is the contract; this file is its prerequisite half, and holds no backend.
//
// Everything here is pure over (Os, environment, filesystem shape), so the macOS answers are
// testable from any host — the technique AgentSandboxLauncher.stateRootOf already uses. A refusal
// is a value rather than an exit, because the same classification serves a launch preflight, a
// channel request, and the tests that prove unsupported layouts stay unsupported.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{InvalidPathException, Path, Paths}
import java.util.Locale

import HostCommands.Os

object BuildSandboxPolicy:

  enum Tool:
    case Sbt, Mill

  /**
   * Why a build cannot run, in the categories PLAN-SBT-ON-HOST.md §10 names. A value, not a
   * message: the wrapper prints one wording, the channel another, and the tests match on neither.
   */
  enum Refusal:
    case PrereqJvmNotCoursier(found: String)
    case PrereqSbtNotCoursier(found: Path)
    case PrereqMillBootstrapMissing
    case PrereqMillVersionUnpinned
    case PrereqMillLauncherMissing(version: String, downloadDir: Path)
    case PrereqSbtBootMissing
    case CacheRootUnusable(reason: String)
    case WorkingDirectoryOutsideProject(requested: String)
    case SessionTmpTooLong(path: Path, max: Int)

  /** Everything settled before a build is asked for; every path canonical. */
  case class BuildPolicy(
    project: Path,
    jdkHome: Path,
    coursierV1: Path,
    tool: Tool,
    launcher: Path,
    sbtBoot: Option[Path],
  )

  // ---------------------------------------------------------------------------
  // Roots
  // ---------------------------------------------------------------------------

  /**
   * The build-cache root, discovered exactly as [[AgentSandboxLauncher.stateRootOf]] discovers the
   * state root so the two answer alike on one machine: XDG_CACHE_HOME when set and absolute,
   * otherwise $HOME/.cache. Unset is the ordinary case on macOS rather than the exception — Mill's
   * own bootstrap takes the same fallback there — so the fallback is the path most runs use.
   */
  def cacheRootOf(os: Os, env: String => Option[String]): Either[Refusal, Path] =
    val (variable, configured) = os match
      case Os.Windows => ("LOCALAPPDATA", env("LOCALAPPDATA"))
      case _ =>
        env("XDG_CACHE_HOME").filter(_.nonEmpty) match
          case Some(value) => ("XDG_CACHE_HOME", Some(value))
          case None        => ("HOME", env("HOME").filter(_.nonEmpty).map(_ + "/.cache"))
    configured.filter(_.nonEmpty) match
      case None => Left(Refusal.CacheRootUnusable(s"$variable is not set"))
      case Some(value) =>
        parsePath(value) match
          case None => Left(Refusal.CacheRootUnusable(s"$variable is not a valid path: '$value'"))
          case Some(path) if !path.isAbsolute =>
            // The same refusal stateRootOf makes, for the same reason: a relative value resolves
            // against the current directory, which is the repository being sandboxed.
            Left(Refusal.CacheRootUnusable(
              s"$variable is '$value', which is not an absolute path",
            ))
          case Some(path) => Right(path.resolve("ko-agent-sandbox").normalize())

  /**
   * This project's build caches, under one directory so `--reset-cache` for a project is a single
   * removal and a further cache kind can join without moving anything.
   *
   * Only Coursier's for now. Mill's launcher is provisioned by the user rather than fetched here,
   * so it has no writable home (BuildSandboxPolicy.millLauncher).
   */
  def agentCacheDir(cacheRoot: Path, projectId: String): Path =
    cacheRoot.resolve("cache").resolve(projectId)

  def agentCoursierV1(cacheRoot: Path, projectId: String): Path =
    agentCacheDir(cacheRoot, projectId).resolve("coursier").resolve("v1")

  /**
   * Refused when the cache root would sit inside the project, the check
   * [[AgentSandboxLauncher.requireStateRootOutside]] makes for the state root: a cache the
   * workspace can reach is a cache the sandbox can rewrite between builds.
   */
  def cacheRootOutsideProject(cacheRoot: Path, project: Path, os: Os): Either[Refusal, Path] =
    if overlaps(cacheRoot, project, os) then
      Left(Refusal.CacheRootUnusable(s"$cacheRoot overlaps the project directory $project"))
    else Right(cacheRoot)

  /** The user's Coursier cache root — read for the JDK, never granted whole (§3.1, §5.1). */
  def coursierCacheRoot(os: Os, env: String => Option[String]): Option[Path] =
    env("COURSIER_CACHE").filter(_.nonEmpty).flatMap(parsePath).map(_.normalize()).orElse:
      env("HOME").filter(_.nonEmpty).flatMap(parsePath).map: home =>
        os match
          case Os.Mac => home.resolve("Library/Caches/Coursier")
          case _      => home.resolve(".cache/coursier")

  /** Where `cs install` puts launchers. The macOS spelling contains a space. */
  def coursierInstallDir(os: Os, env: String => Option[String]): Option[Path] =
    env("COURSIER_BIN_DIR").filter(_.nonEmpty).flatMap(parsePath).map(_.normalize()).orElse:
      env("HOME").filter(_.nonEmpty).flatMap(parsePath).map: home =>
        os match
          case Os.Mac => home.resolve("Library/Application Support/Coursier/bin")
          case _      => home.resolve(".local/share/coursier/bin")

  // ---------------------------------------------------------------------------
  // Prerequisites
  // ---------------------------------------------------------------------------

  /**
   * The JDK the build runs on, from JAVA_HOME alone.
   *
   * `java` on PATH is not a second source. On macOS it is `/usr/bin/java`, a stub that resolves
   * through JAVA_HOME or java_home and so reports the right JVM at the wrong path: validating the
   * binary establishes nothing about what it redirects to.
   *
   * The answer is one canonical home, never a root holding JDKs. A current Coursier unpacks a JDK
   * into its archive cache under a URL-derived path, so the enclosing directory is the general
   * `arc` tree — granting that would hand the build every archive Coursier ever extracted.
   *
   * `canonicalize` resolves symlinks; None means the path does not exist, which is itself a
   * refusal rather than a reason to fall back.
   */
  def resolveJdkHome(
    env: String => Option[String],
    cacheRoot: Path,
    canonicalize: Path => Option[Path],
    os: Os,
  ): Either[Refusal, Path] =
    env("JAVA_HOME").filter(_.nonEmpty) match
      case None => Left(Refusal.PrereqJvmNotCoursier("JAVA_HOME is not set"))
      case Some(value) =>
        parsePath(value).flatMap(canonicalize) match
          case None => Left(Refusal.PrereqJvmNotCoursier(value))
          case Some(home) =>
            canonicalize(cacheRoot) match
              case Some(root) if startsWith(home, root, os) => Right(home)
              case _                                        => Left(Refusal.PrereqJvmNotCoursier(value))

  /**
   * The `sbt` the build runs, which must be the one `cs install sbt` produced. A launcher found on
   * PATH is accepted only when it canonicalizes into the Coursier install directory, so a symlink
   * from PATH into that directory works and one pointing anywhere else does not.
   */
  def validateSbtLauncher(
    candidate: Path,
    installDir: Path,
    canonicalize: Path => Option[Path],
    os: Os,
  ): Either[Refusal, Path] =
    (canonicalize(candidate), canonicalize(installDir)) match
      case (Some(launcher), Some(dir)) if startsWith(launcher, dir, os) => Right(launcher)
      case (Some(launcher), _)                                          => Left(Refusal.PrereqSbtNotCoursier(launcher))
      case _                                                            => Left(Refusal.PrereqSbtNotCoursier(candidate))

  /**
   * Mill's bootstrap, which is the project's own file rather than an installed command: a global
   * Mill is not supported, so its absence is a prerequisite failure and not a reason to look
   * elsewhere.
   */
  def validateMillBootstrap(
    project: Path,
    isExecutableFile: Path => Boolean,
  ): Either[Refusal, Path] =
    val bootstrap = project.resolve("mill")
    if isExecutableFile(bootstrap) then Right(bootstrap)
    else Left(Refusal.PrereqMillBootstrapMissing)

  /**
   * Where a provisioned Mill launcher lives, in the bootstrap's own order of overrides. No platform
   * branch: the script spells its fallback `${XDG_CACHE_HOME:-$HOME/.cache}/mill` everywhere, which
   * is why a macOS host keeps Mill's cache under ~/.cache while Coursier's is under ~/Library.
   */
  def millDownloadDir(env: String => Option[String]): Option[Path] =
    def fromEnv(name: String) = env(name).filter(_.nonEmpty).flatMap(parsePath).map(_.normalize())
    fromEnv("MILL_FINAL_DOWNLOAD_FOLDER")
      .orElse(fromEnv("MILL_USER_CACHE_DIR").map(_.resolve("download")))
      .orElse:
        val base = env("XDG_CACHE_HOME").filter(_.nonEmpty).flatMap(parsePath)
          .orElse(env("HOME").filter(_.nonEmpty).flatMap(parsePath).map(_.resolve(".cache")))
        base.map(_.resolve("mill").resolve("download"))

  /**
   * The pinned Mill version, read the way the bootstrap reads it — and only *read*. The script's
   * own dry-run mode would report the launcher path exactly, but running the project's script is
   * executing agent-authored shell on the host, which is what the sandbox exists to prevent.
   *
   * Unpinned is a refusal rather than the bootstrap's fallback: that fallback is a
   * DEFAULT_MILL_VERSION assignment inside the committed script, and grepping project-controlled
   * shell source to choose which host executable to grant is the wrong shape.
   */
  def millVersion(
    project: Path,
    env: String => Option[String],
    readLines: Path => Option[Seq[String]],
  ): Either[Refusal, String] =
    def firstLine(name: String): Option[String] =
      readLines(project.resolve(name)).flatMap(_.headOption).map(_.trim).filter(_.nonEmpty)
    def tagged(name: String, marker: String): Option[String] =
      readLines(project.resolve(name))
        .flatMap(_.find(line => line.contains("mill-version") && line.contains(marker)))
        .map(trimValue)
        .filter(_.nonEmpty)

    val found = env("MILL_VERSION").filter(_.nonEmpty)
      .orElse(firstLine(".mill-version"))
      .orElse(firstLine(".config/mill-version"))
      .orElse(tagged("build.mill.yaml", "mill-version:"))
      .orElse(tagged("build.mill", "//|"))
      .orElse(tagged("build.mill.scala", "//|"))
    found.filter(plausibleVersion) match
      case Some(version) => Right(version)
      case None          => Left(Refusal.PrereqMillVersionUnpinned)

  /**
   * The launcher for that version, matched on its *prefix*. The bootstrap appends a per-platform,
   * per-version suffix (`-native-mac-aarch64` and others); replicating that case logic is the half
   * that breaks when Mill changes it, and a prefix match never has to.
   */
  def millLauncher(
    downloadDir: Path,
    version: String,
    entries: Path => Seq[String],
  ): Either[Refusal, Path] =
    entries(downloadDir).filter(_.startsWith(version)).sorted.headOption match
      case Some(name) => Right(downloadDir.resolve(name))
      case None       => Left(Refusal.PrereqMillLauncherMissing(version, downloadDir))

  /** The bootstrap's own trim: everything past the last colon, comments and quotes removed. */
  private def trimValue(line: String): String =
    val afterColon = line.lastIndexOf(':') match
      case -1    => line
      case index => line.substring(index + 1)
    afterColon.takeWhile(_ != '#').filter(ch => ch != '\'' && ch != '"').trim

  /** A version names a directory entry, so anything with a separator or space is not one. */
  private def plausibleVersion(value: String): Boolean =
    value.nonEmpty && !value.exists(ch => ch == '/' || ch == '\\' || ch.isWhitespace)

  /** sbt's boot directory, read-only to the build and never provisioned by the sandbox. */
  def sbtBoot(env: String => Option[String], isDirectory: Path => Boolean): Either[Refusal, Path] =
    env("HOME").filter(_.nonEmpty).flatMap(parsePath).map(_.resolve(".sbt/boot")) match
      case Some(boot) if isDirectory(boot) => Right(boot)
      case _                               => Left(Refusal.PrereqSbtBootMissing)

  // ---------------------------------------------------------------------------
  // The session temporary directory
  // ---------------------------------------------------------------------------

  /**
   * How long SESSION_TMP may be. sbt's boot socket lives at
   * `<XDG_RUNTIME_DIR or java.io.tmpdir>/.sbt/sbt-socket<farmHash>/sbt-load.sock` (sbt's
   * BootServerSocket.java), 50 characters past the directory once the hash is a signed 64-bit
   * value, against the 104-byte `sun_path` a macOS UNIX-domain socket allows, NUL included. The
   * server side refuses a longer path with a message; the client's JNI connect has no such check and
   * dies in memcpy with `Trace/BPT trap: 5`. Measured: 52 runs, 56 traps.
   *
   * The wrapper points `XDG_RUNTIME_DIR`, `SBT_GLOBAL_SERVER_DIR` and `java.io.tmpdir` at this one
   * directory, so this is the budget for all three.
   */
  val SessionTmpMaxLength: Int = 104 - 1 - "/.sbt/sbt-socket".length - "-9223372036854775808".length -
    "/sbt-load.sock".length

  def sessionTmpFits(path: Path): Either[Refusal, Path] =
    if path.toString.length <= SessionTmpMaxLength then Right(path)
    else Left(Refusal.SessionTmpTooLong(path, SessionTmpMaxLength))

  // ---------------------------------------------------------------------------
  // The channel's working directory
  // ---------------------------------------------------------------------------

  /**
   * Translate a working directory the sandbox supplied into a host path.
   *
   * This is the one value in the design that arrives from inside the container, so it is validated
   * rather than trusted. It never becomes the profile's PROJECT parameter — that is always the
   * launcher's canonical root — and reaches the backend only as the child's cwd. Validating it
   * anyway is what turns a request naming somewhere else into one answer instead of a wall of
   * denials.
   *
   * `mount` is what the project is mounted at inside the container, `/workspace` today. A request
   * that is not under it, that climbs out with `..`, or whose canonical form leaves the project, is
   * refused; nothing is clamped back to the root.
   */
  def workingDirectory(
    requested: String,
    mount: String,
    project: Path,
    canonicalize: Path => Option[Path],
    os: Os,
  ): Either[Refusal, Path] =
    def refuse = Left(Refusal.WorkingDirectoryOutsideProject(requested))
    val relative =
      if requested == mount then Some("")
      else if requested.startsWith(mount + "/") then Some(requested.drop(mount.length + 1))
      else None
    relative match
      case None => refuse
      case Some(suffix) =>
        parsePath(suffix) match
          // An absolute suffix would resolve away from the project entirely; `..` is normalized
          // first so a textual prefix test cannot be fooled, and the canonical form is then
          // re-checked because a symlink inside the project can still leave it.
          case Some(part) if part.isAbsolute => refuse
          case Some(part) =>
            val joined = project.resolve(part).normalize()
            if !startsWith(joined, project, os) then refuse
            else
              canonicalize(joined) match
                case Some(real) if startsWith(real, project, os) => Right(real)
                case _                                           => refuse
          case None => refuse

  // ---------------------------------------------------------------------------
  // Path comparison
  // ---------------------------------------------------------------------------

  /**
   * Containment, folding case where the platform's filesystem does. APFS is case-insensitive by
   * default, so a comparison that does not fold accepts a path the filesystem treats as the same
   * one — the disagreement `policy.rs`'s `folds_to` exists to prevent on the filter's side.
   */
  def startsWith(path: Path, ancestor: Path, os: Os): Boolean =
    val (child, parent) = (path.normalize(), ancestor.normalize())
    if !foldsCase(os) then child.startsWith(parent)
    else
      // Locale.ROOT, or a Turkish default locale folds 'I' to a dotless 'ı' and two paths the
      // filesystem calls the same stop comparing equal.
      def parts(path: Path): IndexedSeq[String] =
        (0 until path.getNameCount).map(i => path.getName(i).toString.toLowerCase(Locale.ROOT))
      val childParts = parts(child)
      val parentParts = parts(parent)
      child.getRoot == parent.getRoot
        && childParts.length >= parentParts.length
        && childParts.take(parentParts.length) == parentParts

  /** Overlap in either direction: a cache above the project exposes it, one below is writable. */
  def overlaps(left: Path, right: Path, os: Os): Boolean =
    startsWith(left, right, os) || startsWith(right, left, os)

  /** macOS and Windows default to case-insensitive volumes; Linux does not. */
  def foldsCase(os: Os): Boolean = os != Os.Linux

  /** A string that is not a path at all is a refusal, never an exception thrown at a caller. */
  private def parsePath(value: String): Option[Path] =
    try Some(Paths.get(value))
    catch case _: InvalidPathException => None

  /** The real path, or None when it does not exist — an absence the caller classifies. */
  def realPath(path: Path): Option[Path] =
    try Some(path.toRealPath())
    catch case _: IOException => None
