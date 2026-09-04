// What a host build is allowed to touch, decided before any of it runs: where this project's
// disposable build caches live, which JDK and launcher are the Coursier-managed ones, and which
// directory a request from inside the sandbox may name as a working directory. run-on-host.md is
// the reference; this file is the contract's prerequisite half, and holds no backend.
//
// Everything here is pure over (Os, environment, filesystem layout), so the macOS answers are
// testable from any host — the technique AgentSandboxLauncher.stateRootOf already uses. A refusal
// is a value rather than an exit, because the same classification serves a launch preflight, a
// channel request, and the tests that prove unsupported layouts stay unsupported.

package agentsandbox.launcher

import java.io.IOException
import java.nio.file.{InvalidPathException, Path, Paths}
import java.util.Locale

import HostCommands.Os

object RunOnHostPolicy:

  enum Tool:
    case Sbt, Mill

  /**
   * Why a build cannot run, one case per category (run-on-host.md "Failure policy"). A value, not a
   * message: the wrapper prints one wording, the channel another, and the tests match on neither.
   */
  enum Refusal:
    case PrereqJvmNotCoursier(found: String)
    case PrereqSbtNotCoursier(found: Path)
    case PrereqMillBootstrapMissing
    case PrereqMillVersionUnpinned
    case PrereqMillLauncherMissing(version: String, downloadDir: Path)
    case PrereqMillJvmNotSystem(found: Option[String])
    case CacheRootUnusable(reason: String)
    case WorkingDirectoryOutsideProject(requested: String)
    case SessionTmpTooLong(path: Path, max: Int)
    case AllowlistEntryOutsideGrammar(entry: String)

  /** Everything settled before a build is asked for; every path canonical. */
  case class BuildPolicy(
    project: Path,
    jdkHome: Path,
    coursierV1: Path,
    tool: Tool,
    launcher: Path,
  )

  // ---------------------------------------------------------------------------
  // Roots
  // ---------------------------------------------------------------------------

  /**
   * The build-cache root, discovered exactly as [[AgentSandboxLauncher.stateRootOf]] discovers the
   * state root so the two answer alike on one machine: XDG_CACHE_HOME when set and absolute,
   * otherwise $HOME/.cache. Unset is the ordinary case on macOS rather than the exception — mill's
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
   * Coursier's, and sbt's global base. mill's launcher is provisioned by the user rather than
   * fetched here, so it has no writable home (RunOnHostPolicy.millLauncher).
   */
  def agentCacheDir(cacheRoot: Path, projectId: String): Path =
    cacheRoot.resolve("cache").resolve(projectId)

  def agentCoursierV1(cacheRoot: Path, projectId: String): Path =
    agentCacheDir(cacheRoot, projectId).resolve("coursier").resolve("v1")

  /**
   * The confined build's `sbt.global.base`. Persistent and project-scoped on purpose, not in the
   * session temp: sbt 2 writes a content-addressed store under its global base
   * (`cache/v2/{cas,ac}`) and leaves `target/` outputs as symlinks into it — measured on this
   * host, where a build against a session-temporary base would have its own outputs dangle the
   * moment the session directory is removed. Beside the Coursier cache, it shares that cache's poison
   * scope (later builds of the same project, themselves sandboxed) and `--reset-cache`'s removal.
   */
  def agentSbtGlobal(cacheRoot: Path, projectId: String): Path =
    agentCacheDir(cacheRoot, projectId).resolve("sbt-global")

  /**
   * Refused when the cache root would sit inside the project, the check
   * [[AgentSandboxLauncher.requireStateRootOutside]] makes for the state root: a cache the
   * workspace can reach is a cache the sandbox can rewrite between builds.
   */
  def cacheRootOutsideProject(
    cacheRoot: Path,
    project: Path,
    os: Os,
    canonicalize: Path => Either[String, Path],
  ): Either[Refusal, Path] =
    // Canonical before the overlap check: XDG_CACHE_HOME can be a symlink whose text is outside the
    // project and whose target is inside it, and the lexical answer would pass it.
    // Under the macOS data-volume spellings too: a firmlink is not a symlink, so canonicalization
    // leaves `/System/Volumes/Data/...` and `/...` as two names of one directory
    // (SandboxProject.withMacDataVolumeAliases). The canonical root is the answer, and every path
    // derived from it must come from that answer, not from the spelling that was checked.
    def spellings(path: Path): Seq[Path] =
      if os == Os.Mac then SandboxProject.withMacDataVolumeAliases(Seq(path)) else Seq(path)
    canonicalize(cacheRoot) match
      case Left(reason) => Left(Refusal.CacheRootUnusable(reason))
      case Right(root) =>
        // Exact, both being canonical: folding would refuse a case-different sibling that a
        // case-sensitive volume keeps distinct.
        def overlapsExactly(left: Path, right: Path) = left.startsWith(right) || right.startsWith(left)
        if spellings(root).exists(r => spellings(project).exists(p => overlapsExactly(r, p))) then
          Left(Refusal.CacheRootUnusable(s"$root overlaps the project directory $project"))
        else Right(root)

  /** The user's Coursier cache root — read for the JDK, never granted whole
    * (run-on-host.md "The JVM", "The build cache"). */
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
   * refusal rather than a reason to fall back. Both sides canonical, the comparison is exact:
   * canonicalization returns the on-disk spelling on a folding volume, and on a case-sensitive
   * one `coursier` and `Coursier` are different directories that folding would conflate.
   *
   * Inside the cache is necessary, not sufficient: the cache root, `arc` and `v1` are inside it
   * too, and each would be granted read/execute whole. A JDK home is what holds `bin/java`.
   */
  def resolveJdkHome(
    env: String => Option[String],
    cacheRoot: Path,
    canonicalize: Path => Option[Path],
    isExecutableFile: Path => Boolean,
  ): Either[Refusal, Path] =
    env("JAVA_HOME").filter(_.nonEmpty) match
      case None => Left(Refusal.PrereqJvmNotCoursier("JAVA_HOME is not set"))
      case Some(value) =>
        parsePath(value).flatMap(canonicalize) match
          case None => Left(Refusal.PrereqJvmNotCoursier(value))
          case Some(home) =>
            // bin/java canonical and still under the home: a symlink out of it would run a JVM the
            // profile never granted.
            val java = canonicalize(home.resolve("bin").resolve("java"))
            canonicalize(cacheRoot) match
              case Some(root)
                if home.startsWith(root)
                  && home != root
                  && home.getParent != root
                  && java.exists(binary => binary.startsWith(home) && isExecutableFile(binary)) =>
                Right(home)
              case _ => Left(Refusal.PrereqJvmNotCoursier(value))

  /**
   * The `sbt` the build runs, which must be the one `cs install sbt` produced. A launcher found on
   * PATH is accepted only when it canonicalizes into the Coursier install directory, so a symlink
   * from PATH into that directory works and one pointing anywhere else does not.
   */
  def validateSbtLauncher(
    candidate: Path,
    installDir: Path,
    canonicalize: Path => Option[Path],
    isExecutableFile: Path => Boolean,
  ): Either[Refusal, Path] =
    (canonicalize(candidate), canonicalize(installDir)) match
      case (Some(launcher), Some(dir)) if launcher.startsWith(dir) && isExecutableFile(launcher) =>
        Right(launcher)
      case (Some(launcher), _) => Left(Refusal.PrereqSbtNotCoursier(launcher))
      case _                   => Left(Refusal.PrereqSbtNotCoursier(candidate))

  /**
   * The sbt distribution home to grant, from the inner launcher the wrapper execs
   * (SeatbeltProfile.sbtDistribution names it). The executable is checked as the wrapper itself is —
   * canonical, an executable file, still inside the cache once symlinks are followed — and its
   * layout is checked too: `<home>/bin/sbt` with the home strictly inside `arc`, where Coursier
   * unpacks archives. A grant is the home, so `arc/bin/sbt` or `v1/x/bin/sbt` would grant `arc`
   * or a `v1` entry: the layout is what keeps a grant a distribution.
   */
  def validateSbtDistribution(
    inner: Path,
    coursierCache: Path,
    canonicalize: Path => Option[Path],
    isExecutableFile: Path => Boolean,
  ): Either[Refusal, Path] =
    (canonicalize(inner), canonicalize(coursierCache)) match
      case (Some(executable), Some(cache)) if isExecutableFile(executable) =>
        val arc = cache.resolve("arc")
        val home = Option(executable.getParent).flatMap(bin => Option(bin.getParent))
          .filter(_ => executable.getFileName.toString == "sbt" && executable.getParent.getFileName.toString == "bin")
          .filter(home => home.startsWith(arc) && home != arc)
        home.toRight(Refusal.PrereqSbtNotCoursier(executable))
      case (Some(executable), _) => Left(Refusal.PrereqSbtNotCoursier(executable))
      case _                     => Left(Refusal.PrereqSbtNotCoursier(inner))

  /**
   * mill's bootstrap, which is the project's own file rather than an installed command: a global
   * mill is not supported, so its absence is a prerequisite failure and not a reason to look
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
   * Where a provisioned mill launcher lives, as the bootstrap computes it: `MILL_FINAL_DOWNLOAD_FOLDER`
   * if set, else `${XDG_CACHE_HOME:-$HOME/.cache}/mill/download`. `MILL_USER_CACHE_DIR` is not an
   * input — the script assigns it and never reads it. No platform branch: the fallback is spelled
   * the same everywhere, which is why a macOS host keeps mill's cache under ~/.cache while
   * Coursier's is under ~/Library.
   */
  def millDownloadDir(env: String => Option[String]): Option[Path] =
    def fromEnv(name: String) = env(name).filter(_.nonEmpty).flatMap(parsePath).map(_.normalize())
    fromEnv("MILL_FINAL_DOWNLOAD_FOLDER").orElse:
      val base = fromEnv("XDG_CACHE_HOME")
        .orElse(fromEnv("HOME").map(_.resolve(".cache")))
      base.map(_.resolve("mill").resolve("download"))

  /**
   * The mill version, read the way the bootstrap reads it — and only *read*. The script's own
   * dry-run mode would report the launcher path exactly, but running the project's script is
   * executing agent-authored shell on the host, which is what the sandbox exists to prevent.
   *
   * The fallback is the bootstrap's: `DEFAULT_MILL_VERSION` from the environment, else the
   * assignment at the top of the script, which mill documents as the recommended way to manage
   * the version (`./mill updateMillScripts`). The file sources are all project files and the two
   * environment overrides are the wrapper's; whichever names the version, what is granted is a
   * launcher the user provisioned.
   */
  def millVersion(
    project: Path,
    env: String => Option[String],
    readLines: Path => Option[Seq[String]],
  ): Either[Refusal, String] =
    // The script's `elif` chain: the first file that *exists* decides, and what it yields is the
    // answer even when empty — there is no fall-through to the next file. A version file gives
    // its first line as is; a marker file gives every matching line, trimmed, so two markers give
    // a value with a newline in it, which is no version.
    def lines(name: String): Option[Seq[String]] = readLines(project.resolve(name))
    def versionFile(name: String): Option[Option[String]] = lines(name).map(_.headOption)
    def markerFile(name: String, marker: String => Boolean): Option[Option[String]] =
      lines(name).map(all => Some(all.filter(marker).map(trimValue).mkString("\n")))
    val buildScript = Seq("build.mill", "build.mill.scala", "build.sc").find(name => lines(name).isDefined)

    def scriptDefault: Option[String] =
      lines("mill").flatMap(_.collectFirst { case DefaultAssignment(version) => version })

    val found: Option[String] = env("MILL_VERSION").filter(_.nonEmpty)
      .orElse:
        versionFile(".mill-version")
          .orElse(versionFile(".config/mill-version"))
          .orElse(markerFile("build.mill.yaml", _.contains("mill-version:")))
          .orElse(buildScript.flatMap(markerFile(_, ScriptMarker.matches)))
          .flatten
          .filter(_.nonEmpty)
      .orElse(env("DEFAULT_MILL_VERSION").filter(_.nonEmpty))
      .orElse(scriptDefault)
    found.filter(plausibleVersion) match
      case Some(version) => Right(version)
      case None          => Left(Refusal.PrereqMillVersionUnpinned)

  /**
   * The file the bootstrap will run for a pinned version, as it derives it (the `case
   * "$MILL_VERSION"` block of the official `mill` script): a `-native` suffix is stripped and the
   * platform suffix applied; a `-jvm` suffix is stripped and nothing applied; otherwise the
   * platform suffix applies to every version past 0.12, and none to 0.1–0.12, which were jars.
   * `arch` is `uname -m`'s answer: `arm64` on Apple silicon, `x86_64` otherwise. macOS only, as
   * the feature is.
   */
  def millLauncherName(version: String, arch: String): String =
    val native = if arch == "arm64" then "-native-mac-aarch64" else "-native-mac-amd64"
    val jarEra = raw"0\.([1-9]|1[0-2])\..*".r
    if version.endsWith("-native") then version.stripSuffix("-native") + native
    else if version.endsWith("-jvm") then version.stripSuffix("-jvm")
    else if jarEra.matches(version) then version
    else version + native

  /**
   * `mill-jvm-version` must be `system`: mill otherwise provisions a JVM through Coursier's
   * index, a JDK fetched by the build, where `system` takes `java` from the PATH the wrapper sets.
   *
   * Read as the launcher reads it (`MillProcessLauncher.loadMillConfig`, `mill.constants.Util.
   * readBuildHeader`): `.mill-jvm-version`, else `.config/mill-jvm-version` — the first line that is
   * not blank or a `#` comment, compared as written, so `" system "` is not `system` — else the
   * header of the first root build file that exists, `build.mill.yaml` (the whole file is YAML)
   * then `build.mill` (the initial run of `//| ` lines only), where the key is a top-level YAML
   * key. The first source that exists is authoritative, empty or not; anything but `system` is a
   * refusal, absent included, since absent means mill's own default.
   */
  def millJvmIsSystem(
    project: Path,
    readLines: Path => Option[Seq[String]],
  ): Either[Refusal, Unit] =
    def lines(name: String): Option[Seq[String]] = readLines(project.resolve(name))
    // No environment interpolation, though mill's reader does it: a value that needs the
    // environment to become `system` is not literally `system`, and refusing it fails closed.
    def optsFile(name: String): Option[Option[String]] =
      lines(name).map(_.find(line => line.trim.nonEmpty && !line.trim.startsWith("#")))
    // A recognizer, not a YAML parser: the only question is "is this exactly `system`?", so the
    // accepted spellings are enumerated — plain or quoted, an optional comment after whitespace,
    // as YAML requires — and every other value, `system#x` and an unmatched quote included, is
    // returned as found and refused below. Conservative false rejects fail closed; a parser that
    // guessed would fail open.
    def topLevel(all: Seq[String]): Option[String] =
      // mill parses one YAML document; a `---` or `...` marker starts territory it never reads,
      // and a key there would be recognized here and ignored there. Refused, and the refusal is the value.
      if all.exists(line => DocumentMarker.matches(line)) then Some("multi-document YAML")
      else all.collect { case TopLevelJvmKey(value) => value } match
        case Seq()      => None
        case Seq(value) => Some(if SystemSpelling.matches(value) then "system" else value.trim)
        // Which one mill's parsed map keeps is its parser's business; two keys are never `system`.
        case _ => Some("duplicate mill-jvm-version keys")
    // The //| lines as readBuildHeader takes them: `//|` alone is an empty line, `//| ...` is
    // data, anything else starting `//|` is an error, and so is a `//|` line after the initial
    // run — it scans the whole file. An error there is a refusal here, returned as the value.
    def header(name: String): Option[Option[String]] =
      lines(name).map: all =>
        val run = if name.endsWith(".yaml") then Right(all)
          else
            val (initial, rest) = all.span(_.startsWith("//|"))
            if initial.exists(line => line != "//|" && !line.startsWith("//| ")) then Left("malformed //| header")
            else if rest.exists(_.startsWith("//|")) then Left("stray //| line after the header")
            else Right(initial.map(line => if line == "//|" then "" else line.drop(4)))
        run.fold(reason => Some(reason), topLevel)
    val found: Option[String] =
      optsFile(".mill-jvm-version")
        .orElse(optsFile(".config/mill-jvm-version"))
        .orElse(header("build.mill.yaml"))
        .orElse(header("build.mill"))
        .flatten
    if found.contains("system") then Right(()) else Left(Refusal.PrereqMillJvmNotSystem(found))

  /** `---` or `...` at line start, bare or followed by whitespace and anything: both start
    * territory mill's single-document parse never reads. */
  private val DocumentMarker = raw"""(?:---|\.\.\.)(?:\s.*)?""".r

  /** The colon must be followed by whitespace or end the line: YAML's `key:value` is one scalar,
    * not a mapping, and mill would not see the key. */
  private val TopLevelJvmKey = raw"""mill-jvm-version:((?:\s.*)?)""".r
  private val SystemSpelling = raw"""\s*(?:system|"system"|'system')(?:\s+#.*)?\s*""".r

  /** That file, provisioned: present and executable, or a refusal naming what `./mill` would fix. */
  def millLauncher(
    downloadDir: Path,
    version: String,
    arch: String,
    isExecutableFile: Path => Boolean,
  ): Either[Refusal, Path] =
    val launcher = downloadDir.resolve(millLauncherName(version, arch))
    if isExecutableFile(launcher) then Right(launcher)
    else Left(Refusal.PrereqMillLauncherMissing(version, downloadDir))

  /** `DEFAULT_MILL_VERSION="1.1.8"` as the bootstrap spells it, inside its `if [ -z … ]` guard. */
  private val DefaultAssignment = raw""".*\bDEFAULT_MILL_VERSION="([^"]+)".*""".r

  /** The bootstrap's `grep -E "//\\|.*mill-version"`: the marker, then the key, in that order. */
  private val ScriptMarker = raw".*//\|.*mill-version.*".r

  /** The bootstrap's own trim: everything past the last colon, comments and quotes removed. */
  private def trimValue(line: String): String =
    val afterColon = line.lastIndexOf(':') match
      case -1    => line
      case index => line.substring(index + 1)
    afterColon.takeWhile(_ != '#').filter(ch => ch != '\'' && ch != '"').trim

  /** A version names a directory entry, so anything with a separator or space is not one. */
  private def plausibleVersion(value: String): Boolean =
    value.nonEmpty && !value.exists(ch => ch == '/' || ch == '\\' || ch.isWhitespace)

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
  // The build's egress allowlist
  // ---------------------------------------------------------------------------

  /** Coursier's and sbt's default artifact repository: the one host every build's proxy admits. */
  val MavenCentralHost = "repo1.maven.org"

  def buildAllowlistPath(project: Path, tool: Tool): Path =
    project.resolve(".ko-agent-sandbox").resolve("host-command")
      .resolve(tool.toString.toLowerCase(java.util.Locale.ROOT)).resolve("egress").resolve("rule")

  /** The one line form the build's rule file holds, `allow https://<host>/ read`, as the refusal spells it. */
  val BuildAllowlistForm = "allow https://<host>/ read"

  /**
   * The build's rule file grammar: `allow https://<host>/ read` lines and `#` comments, nothing
   * else — no other grant, no path, no provider, no deny. The proxy's full grammar would let one
   * `allow model-provider` line expand into endpoints that are no artifact repository, and a
   * `tunnel` word means nothing to a proxy running without inspection; anything outside the subset
   * is refused here, never passed through for the proxy to interpret. Tokenization mirrors the
   * proxy's — split on whitespace, a comment from the first token starting with `#`, and a `#`
   * inside a token refused — so a line read here is the line the proxy would read, and
   * `read#typo` is not `read`; the host is what the proxy's own parser will normalize and vet.
   */
  def buildAllowlist(text: String): Either[Refusal, Vector[String]] =
    val entries = text.linesIterator
      .map(_.split("\\s+").toVector.filter(_.nonEmpty).takeWhile(!_.startsWith("#")))
      .filter(_.nonEmpty)
      .toVector
    def hostOf(tokens: Vector[String]): Option[String] = tokens match
      case Vector("allow", url, "read") if url.startsWith("https://") && url.endsWith("/") && !url.contains('#') =>
        val host = url.drop("https://".length).dropRight(1)
        Option.when(host.nonEmpty && !host.contains('/') && !host.startsWith("*"))(host)
      case _ => None
    entries.find(hostOf(_).isEmpty) match
      case Some(outside) => Left(Refusal.AllowlistEntryOutsideGrammar(outside.mkString(" ")))
      case None          => Right(entries.flatMap(hostOf).distinct)

  /**
   * The proxy's rule input for a build: `deny defaults`, then Maven Central, then the file's
   * lines — the whole policy stated, so the container's catalog contributes nothing. Deduplicated,
   * so a host the file restates is not warned as a redundant grant at every build.
   */
  def egressRuleText(fileHosts: Vector[String]): String =
    ("deny defaults" +: (MavenCentralHost +: fileHosts).distinct.map(host => s"allow https://$host/ read"))
      .mkString("\n")

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
                // Exact: `real` and `project` are both canonical, so their spellings are the
                // volume's own, and folding would admit a case-different sibling on a
                // case-sensitive volume.
                case Some(real) if real.startsWith(project) => Right(real)
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
