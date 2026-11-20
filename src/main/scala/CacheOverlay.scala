// `--cache-overlay`: a host cache that a session reads through podman's `:O` overlay (doc/plan-coursier.md). The host
// directory is the overlay's lower layer, and the session writes into a private upper layer that podman removes with
// the container. The session therefore reads the host cache and never changes it.
// - Each kind fixes its host discovery and its container destination. The option names no arbitrary source or
//   destination: a destination of the caller's choice could shadow the workspace, the managed settings or the agents'
//   state.
// - Podman documents `O` as conflicting with the other volume options, so the mount carries no `ro`, `z` or `U`, and
//   the launcher never relabels or chowns the host cache.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

import FileHelper.realPath
import HostCommands.*
import SandboxWorkspace.{ContainerHome, HomeProtection, homeOrHolder, mountPathOf, overlapsInAnySpelling}

object CacheOverlay:

  final val OptionName = "--cache-overlay"

  /** The kinds that the option accepts. A kind enters this set only with its own boundary analysis
    * (doc/plan-coursier.md, "Deliberate exclusions"). */
  enum Kind(val name: String, val destination: String):
    /** Coursier's download cache alone. Its `arc` and `jvm` siblings hold unpacked archives, which can be specific to
      * the host OS, so they stay session-local. */
    case Coursier extends Kind("coursier", s"$ContainerHome/.cache/coursier/v1")

  /** `--cache-overlay=<kind>`, which discovers the host cache, or `--cache-overlay=<kind>=<directory>`. */
  case class Request(kind: Kind, directory: Option[String]):
    def spelled: String = s"$OptionName=${kind.name}${directory.fold("")("=" + _)}"

  /**
   * One value of the option. The value splits at its first `=` alone, so a Windows drive's `:` and any `=` or `,` in
   * the directory stay part of the directory, for `refusal` to judge.
   */
  def parse(value: String): Either[String, Request] =
    val (name, rest) = value.span(_ != '=')
    Kind.values.find(_.name == name) match
      case None =>
        Left(s"error: $OptionName=$value; the kinds are ${Kind.values.map(_.name).mkString(", ")}, exactly")
      case Some(kind) if rest.isEmpty => Right(Request(kind, None))
      case Some(kind) =>
        val directory = rest.drop(1)
        if directory.isEmpty then
          Left(s"error: $OptionName=$value; name the cache's directory after '=', or drop '=' to find the cache")
        else
          RunOnHostPrereqs.absolute("the directory", directory) match
            case Left(_)  => Left(s"error: $OptionName=$value; the directory must be an absolute path")
            case Right(_) => Right(Request(kind, Some(directory)))

  /**
   * Where Coursier keeps its download cache: `COURSIER_CACHE`'s exact value when the variable is set, else `v1` under
   * the platform's Coursier cache directory (RunOnHostPrereqs.coursierCacheBase).
   * - `rawEnv` reads a set but empty variable as set, as Coursier does. Coursier would read an empty or relative value
   *   against whichever directory it runs in, so such a value is refused rather than guessed.
   */
  def coursierDownloadCache(os: Os, rawEnv: String => Option[String]): Either[String, Path] =
    rawEnv("COURSIER_CACHE") match
      case Some(value) => RunOnHostPrereqs.absolute("COURSIER_CACHE", value)
      case None        => RunOnHostPrereqs.coursierCacheBase(os, rawEnv).map(_.resolve("v1"))

  /** A host directory that the cache may not overlap in either direction, as a refusal names it: "the workspace,
    * which the session writes". */
  case class Protected(directory: Path, what: String)

  /** The cache that a launch mounts, canonical. */
  case class Resolved(kind: Kind, directory: Path):
    /** One `--volume` value ending in `:O`, which podman documents as conflicting with every other volume option. */
    def volumeArg: String = s"--volume=$directory:${kind.destination}:O"

  /**
   * Why the canonical `cache` must not become an overlay, or None. The launcher refuses:
   *   - a filesystem root;
   *   - a home directory, a directory that holds one, and another user's home (SandboxWorkspace.homeOrHolder), each of
   *     which exposes credentials;
   *   - a path that podman cannot take as a `--volume` source (SandboxWorkspace.mountPathOf): a POSIX path with a `:`,
   *     or a Windows path without a drive letter, such as a UNC path;
   *   - a path with a `,`: podman's overlay writes the path into the mount's `lowerdir=` option, escaping only `:`, and
   *     then splits the options at commas, so the rest of the name would become mount options that the launcher did not
   *     choose (https://github.com/containers/podman/blob/v6.2.0/vendor/go.podman.io/buildah/pkg/overlay/overlay_linux.go#L91-L117);
   *   - a POSIX path with a `\`: overlayfs reads a `\` in `lowerdir=` as an escape (`ovl_unescape` in the kernel's
   *     fs/overlayfs/params.c), so the mount would read another directory than the one checked here. A Windows path's
   *     `\` separators become `/` in the machine's spelling;
   *   - an overlap in either direction with a protected directory, in any of the host's spellings of either. A cache
   *     inside a directory that the session writes would let the session change what later sessions read through the
   *     overlay; a cache holding a protected directory would expose it.
   *   - on Linux, a home and an overlap through a mount (homeThroughMount, sharedThroughMount): a bind mount shows one
   *     directory at a second path, which no comparison of paths finds.
   * A directory inside a home passes, the defaults included: the option is permission to read every file under it.
   */
  def refusal(
    cache: Path,
    homes: HomeProtection,
    protectedDirectories: Vector[Protected],
    os: Os,
    mounts: Vector[Mount],
  ): Option[String] =
    if cache.getParent == null then Some("it is a filesystem root")
    else if homeOrHolder(cache, homes) then
      Some("it is a home directory, or holds one, whose credentials it would expose")
    else if os == Os.Linux && rootMount(mounts).isEmpty then
      Some("/proc/self/mountinfo lists no root mount, so the directory behind the path cannot be checked")
    else if homeThroughMount(cache, homes, mounts) then
      Some("a mount shows it as a home directory, or as a directory that holds one, whose credentials it would expose")
    else if mountPathOf(os, cache).isLeft then
      Some("podman cannot mount it: a path with a ':', or a Windows path without a drive letter")
    else if cache.toString.contains(',') then Some("podman's overlay cannot mount a path with a ','")
    else if os != Os.Windows && cache.toString.contains('\\') then
      Some("overlayfs reads a '\\' in the path as an escape, and would mount another directory")
    else
      protectedDirectories.find(root => overlapsInAnySpelling(os, cache, root.directory))
        .map(root => s"it holds or is inside ${root.what}")
        .orElse(
          protectedDirectories.find(root => sharedThroughMount(cache, root.directory, mounts))
            .map(root => s"a mount shows it, or a directory it holds or is inside, within ${root.what}"),
        )

  /** One line of /proc/self/mountinfo (proc_pid_mountinfo(5)): the mount's id and its parent's, the file system's
    * device, the directory of that file system the mount shows, and where the mount shows it. */
  case class Mount(id: String, parent: String, device: String, root: Path, mountPoint: Path)

  /** The mounts of a /proc/self/mountinfo text, in its order. The kernel spells a space, tab, newline or `\` in a path
    * as an octal escape, such as `\040`. */
  def parseMountInfo(text: String): Vector[Mount] =
    def unescaped(field: String) = raw"\\([0-7]{3})".r.replaceAllIn(field, found =>
      java.util.regex.Matcher.quoteReplacement(Integer.parseInt(found.group(1), 8).toChar.toString),
    )
    text.linesIterator.map(_.split(' ')).collect:
      case fields if fields.length > 4 =>
        Mount(fields(0), fields(1), fields(2), Path.of(unescaped(fields(3))), Path.of(unescaped(fields(4))))
    .toVector

  /**
   * The mount that shows `path`, found as path lookup finds it: from the root mount, cross into the child mount at the
   * first mount point on the path, and at each mount point into the mount stacked last on it. A mount below an
   * overmounted directory stays in mountinfo, but its parent is the hidden mount, so the walk never reaches it.
   * - None when no root mount is listed (rootMount).
   */
  private def visible(path: Path, mounts: Vector[Mount]): Option[Mount] =
    def stackTop(mount: Mount): Mount =
      mounts.filter: child =>
        child.parent == mount.id && child.id != mount.id && child.mountPoint == mount.mountPoint
      .lastOption.fold(mount)(stackTop)
    @annotation.tailrec def walk(current: Mount): Mount =
      val crossings = mounts.filter: child =>
        child.parent == current.id && child.mountPoint != current.mountPoint && path.startsWith(child.mountPoint)
      crossings.map(_.mountPoint.getNameCount).minOption match
        case None        => current
        case Some(depth) => walk(stackTop(crossings.filter(_.mountPoint.getNameCount == depth).last))
    rootMount(mounts).map(root => walk(stackTop(root)))

  /** The mount at `/` whose parent is outside the list or itself: mountinfo lists the root of the reading process's
    * namespace either way (proc_pid_mountinfo(5)). */
  private def rootMount(mounts: Vector[Mount]): Option[Mount] =
    val ids = mounts.map(_.id).toSet
    mounts.filter: mount =>
      mount.mountPoint == Path.of("/") && (mount.parent == mount.id || !ids.contains(mount.parent))
    .lastOption

  /** Where `path` lives in its file system, as the device and the path inside it. */
  private def underlying(path: Path, mounts: Vector[Mount]): Option[(String, Path)] =
    visible(path, mounts).map: mount =>
      (mount.device, mount.root.resolve(mount.mountPoint.relativize(path).toString))

  /**
   * Whether a mount shows the canonical `cache` as a home, a directory that holds one, or another user's home: the
   * rule of SandboxWorkspace.homeOrHolder, applied to the directories behind the paths. A cache inside a home passes.
   * - The homes are the known ones and the visible mounts directly in a directory of homes, such as another user's
   *   home on a device of its own.
   */
  def homeThroughMount(cache: Path, homes: HomeProtection, mounts: Vector[Mount]): Boolean =
    val mountedHomes = mounts.filter: mount =>
      Option(mount.mountPoint.getParent).exists(homes.containers.contains) &&
        visible(mount.mountPoint, mounts).contains(mount)
    val knownHomes = homes.paths.flatMap(underlying(_, mounts)) ++ mountedHomes.map(mount => (mount.device, mount.root))
    underlying(cache, mounts).exists: (device, inside) =>
      knownHomes.exists((homeDevice, home) => homeDevice == device && home.startsWith(inside)) ||
        homes.containers.flatMap(underlying(_, mounts))
          .exists((holderDevice, holder) => holderDevice == device && Option(inside.getParent).contains(holder))

  /**
   * Whether the canonical `cache` and `protectedDirectory` overlap in their file system, though their paths do not: the
   * cache's underlying directory overlaps, in either direction, the underlying directory of `protectedDirectory` or of
   * a visible mount below it. A bind mount of the cache inside the workspace is such a mount.
   * - Mounts below the cache are not compared: an overlay's lower layer does not show the mounts below it.
   */
  def sharedThroughMount(cache: Path, protectedDirectory: Path, mounts: Vector[Mount]): Boolean =
    underlying(cache, mounts).exists: (device, inside) =>
      val below = mounts.filter(mount => mount.mountPoint.startsWith(protectedDirectory))
        .filter(mount => mount.mountPoint != protectedDirectory && visible(mount.mountPoint, mounts).contains(mount))
      val shown = underlying(protectedDirectory, mounts).toVector ++ below.map(mount => (mount.device, mount.root))
      shown.exists((shownDevice, root) => shownDevice == device && (inside.startsWith(root) || root.startsWith(inside)))

  /**
   * The cache that `request` names, canonical and checked, or the refusal.
   * - macOS refuses the option: podman's libkrun machine shows the overlay every host file as the container root's, so
   *   the session could read the cache but add nothing to its directories (doc/plan-coursier.md, "Platform contract").
   * - The launcher creates no cache: the user asked to reuse one, so a missing directory refuses the launch rather than
   *   falling back to the session's own cache.
   * - `containerReadable` answers whether an SELinux-enforcing host lets the container read the directory unrelabeled.
   * - `mounts` are the Linux host's mounts (parseMountInfo), empty elsewhere.
   * - `sessionCanCreate` answers whether the session can create a file in the upper layer's root, as Coursier does: it
   *   writes its `.structure.lock` at the cache root before it creates an artifact's directory (coursier's
   *   `CachePath`). The launcher asks on native Linux alone (sessionCanCreateOnLinux).
   */
  def resolve(
    request: Request,
    os: Os,
    rawEnv: String => Option[String],
    homes: HomeProtection,
    protectedDirectories: Vector[Protected],
    containerReadable: Path => Boolean,
    sessionCanCreate: Path => Boolean,
    mounts: Vector[Mount],
  ): Either[String, Resolved] =
    def refuse(reason: String): Left[String, Nothing] = Left(s"error: ${request.spelled}; $reason")
    val nameIt = s"name the cache instead: $OptionName=${request.kind.name}=<directory>"
    val located = request.directory match
      case Some(spelled) => Right(Path.of(spelled))
      case None =>
        request.kind match
          case Kind.Coursier => coursierDownloadCache(os, rawEnv)
    val roots = protectedDirectories.map: root =>
      root.copy(directory = realPath(root.directory).getOrElse(root.directory.toAbsolutePath.normalize))
    if os == Os.Mac then refuse(MacRefusal)
    else located match
      case Left(reason) => refuse(s"$reason; $nameIt")
      case Right(path) =>
        realPath(path) match
          case None =>
            refuse(s"there is no directory ${pathInline(path, os)}, and the launcher creates no cache; $nameIt")
          case Some(directory) if !Files.isDirectory(directory) => refuse(s"${pathInline(directory, os)} is a file")
          case Some(directory) =>
            refusal(directory, homes, roots, os, mounts) match
              case Some(reason) => refuse(s"${pathInline(directory, os)}: $reason")
              case None if !containerReadable(directory) =>
                refuse(
                  s"the SELinux context of ${pathInline(directory, os)} does not allow container reads; label it " +
                    s"on the host first: chcon -R -t container_file_t -l s0 ${displayPath(directory, os)}",
                )
              case None if !sessionCanCreate(directory) =>
                refuse(
                  s"you lack write or search permission on ${pathInline(directory, os)}, so the session could not " +
                    s"add to the cache; grant both, as chmod u+wx ${displayPath(directory, os)} does on a directory " +
                    "you own, or name another cache",
                )
              case None => Right(Resolved(request.kind, directory))

  /** The refusal on macOS, where the launch refuses before it looks for the cache. */
  val MacRefusal: String =
    "macOS is not supported: through the overlay, podman's macOS machine shows the session every cache file as " +
      "root's, so the session could add nothing to the cache. --run-on-host=sbt keeps its build caches across " +
      "sessions instead"

  /**
   * Whether the session's user may create a file in the overlay's upper root on native Linux. Podman creates that root
   * in its own storage with the cache directory's mode, uid and gid (buildah's `pkg/overlay`), and `--userns=keep-id`
   * maps the uid and gid of podman's process, which this process passes on, to the session's user. The macOS
   * machine's share and WSL's DrvFs present ownership and modes of their own, which no host check predicts.
   * - The check reads the mode rather than asking `access(2)`, which also refuses a cache on a read-only filesystem,
   *   where the upper root stays writable.
   * - The ids come from /proc/self/status, since the JVM's `UnixSystem` gives the account's group, not the process's,
   *   after `newgrp`.
   */
  def sessionCanCreateOnLinux(directory: Path): Boolean =
    val status = Files.readAllLines(Path.of("/proc/self/status")).asScala.toVector
    def realId(field: String): Int =
      statusId(status, field).getOrElse(throw IllegalStateException(s"/proc/self/status has no $field line"))
    creatableBy(
      Files.getAttribute(directory, "unix:mode").asInstanceOf[Int],
      Files.getAttribute(directory, "unix:uid").asInstanceOf[Int],
      Files.getAttribute(directory, "unix:gid").asInstanceOf[Int],
      realId("Uid"),
      realId("Gid"),
    )

  /** The real id on the `Uid:` or `Gid:` line of /proc/self/status. Linux prints ids unsigned, and the JDK's
    * `unix:uid` and `unix:gid` hold the same 32 bits as an `Int`. */
  def statusId(status: Seq[String], field: String): Option[Int] =
    status.collectFirst:
      case line if line.startsWith(s"$field:") =>
        Integer.parseUnsignedInt(line.drop(field.length + 1).trim.split("\\s+").head)

  /** Whether `userUid` with group `userGid` may create a file in a directory of `mode`, `uid` and `gid`: the class of
    * permission bits that the kernel picks must grant both write and search. */
  def creatableBy(mode: Int, uid: Int, gid: Int, userUid: Int, userGid: Int): Boolean =
    val shift = if uid == userUid then 6 else if gid == userGid then 3 else 0
    ((mode >> shift) & 3) == 3

  /** The launch's line for one overlay. The line marks the overlay as a loosening whose grant is the host cache
    * (HostCommands.weakened). */
  def line(resolved: Resolved, source: String, os: Os, color: Boolean = colorStderr): String =
    weakened(s"cache overlay: ${resolved.kind.name}$source", color) +
      s"; the session reads ${pathInline(resolved.directory, os)}, and its writes there are discarded"
