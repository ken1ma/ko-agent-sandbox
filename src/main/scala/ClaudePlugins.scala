// --claude-plugin-dir=<dir>: a Claude Code plugin directory of the host's, mounted read-only into the
// sandbox and named to Claude Code's managed settings, so that its hooks and its mod run under the
// image's allowManagedHooksOnly, which blocks every plugin a session installs.

package agentsandbox.launcher

import java.io.{IOException, UncheckedIOException}
import java.nio.file.{Files, LinkOption, Path}
import java.nio.file.attribute.BasicFileAttributes
import scala.jdk.CollectionConverters.*

import FileHelper.{hasSecondName, realPath}
import HostCommands.{fileBind, Os}
import SandboxProject.overlapsInAnySpelling

object ClaudePlugins:

  val OptionName = "--claude-plugin-dir"

  /**
   * Claude Code runs a plugin's hooks and mod under `allowManagedHooksOnly` only when it counts
   * as the organization's: managed `enabledPlugins` enables it, managed `extraKnownMarketplaces`
   * names its marketplace as a `directory` by absolute path, and the marketplace lists it by a
   * relative path (https://code.claude.com/docs/en/plugins/mods/admin, "Install your
   * organization's mods"). The launcher makes that marketplace per run: the root is a directory
   * it generates, each plugin a bind of the host directory under it, and the drop-in below
   * names both. A plugin loaded this way is `<name>@host`, `<name>` being the directory's name:
   * the marketplace entry's name, which the manifest's own `name` does not have to equal.
   */
  val MountRoot = "/etc/claude-code/host-plugins"
  val MarketplaceName = "host"
  val MarketplaceFile = ".claude-plugin/marketplace.json"
  val ManifestFile = ".claude-plugin/plugin.json"
  val DropInFile = "50-host-plugins.json"
  val DropInPath = s"/etc/claude-code/managed-settings.d/$DropInFile"

  /** The plugin directory, under the run's files, that the generated marketplace manifest sits in. */
  val RunFilesDirectory = "claude-plugins"

  /**
   * The plugins the image loads through `CLAUDE_CODE_PLUGIN_DIRS` (the sandbox Containerfile), as
   * `<name>@inline`. A managed id locks its name: a host plugin of the same name would keep the
   * image's copy from loading (https://code.claude.com/docs/en/plugins/loading, "Name conflicts").
   */
  val ImagePluginNames = Vector("ko-review")
  /** A mod whose one hook draws a band: a launch with it measures whether the hooks run as managed. */
  val ProbePlugin = "src/test/claude-plugins/managed-probe"

  /** The characters a plugin id's parts may use (the marketplace reference, "Plugin entries"). */
  private val EntryName = raw"[A-Za-z0-9][A-Za-z0-9._-]*".r

  /** A plugin the launch mounts: its entry name, the directory's name, and the directory's real path. */
  case class Plugin(name: String, directory: Path):
    def id: String = s"$name@$MarketplaceName"
    def mountPath: String = s"$MountRoot/$name"

  /** A plugin with the name its manifest gives it, which Claude Code compares plugins by. */
  private case class Resolved(plugin: Plugin, manifestName: String)

  /**
   * A directory the session writes, itself or through a host command `--run-on-host` lets it run,
   * and `what` it is, as the refusal names it: "the project directory, which the session writes".
   */
  case class SessionWritten(directory: Path, what: String)

  /**
   * The plugins for the directories as spelled, or why one is refused. Each refusal names the
   * option as spelled. Refused:
   *   - a path that is not a directory, or not a plugin (no `.claude-plugin/plugin.json`: the
   *     marketplace root passed in place of one of its plugins is the likely mistake);
   *   - a manifest that is not JSON, or whose `name` is not a string;
   *   - a directory name that cannot be a plugin id;
   *   - a directory name or manifest name that is an image plugin's, or that an earlier plugin of
   *     the launch has: Claude Code loads one hooks module per manifest name and leaves the other's
   *     out (the loading reference, "Hooks when two enabled plugins share a name");
   *   - a directory that holds or is inside one of `written`, in any of the host's spellings of
   *     either: the project, and the directories `--run-on-host` commands write, where a mod would
   *     be the session's to change and the next launch's to run;
   *   - a symlink under the directory, which Claude Code does not follow out of a plugin either;
   *   - an entry that is neither a regular file nor a directory: a Windows junction, which Java
   *     reports as a directory and not as a symlink, so a walk would enter it, a device or a pipe;
   *   - a file with a second name, which a write through that name changes in place, or whose
   *     names the host cannot count;
   *   - where `containerReadable` says so, a directory an SELinux-enforcing host would let the
   *     container read only after a relabel, a host-metadata write on the user's directory the
   *     launcher does not make.
   */
  def resolve(
    spelled: Vector[String],
    written: Vector[SessionWritten],
    os: Os,
    containerReadable: Path => Boolean,
  ): Either[String, Vector[Plugin]] =
    val roots = written.map: root =>
      root.copy(directory = realPath(root.directory).getOrElse(root.directory.toAbsolutePath.normalize))
    def refuse(spelling: String, reason: String): Left[String, Nothing] =
      Left(s"error: $OptionName=$spelling; $reason")
    /** The plugin, once its directory is one the launch may mount: the name checks and the walk. */
    def named(spelling: String, directory: Path): Either[String, Resolved] =
      val name = Option(directory.getFileName).map(_.toString).getOrElse("")
      if !EntryName.matches(name) then
        refuse(spelling, s"the directory's name, $name, is not a plugin id: letters, digits, '.', '_' and '-'")
      else if ImagePluginNames.contains(name) then
        refuse(spelling, s"$name is a plugin of the image's, and a host plugin of that name would displace it")
      else manifestName(directory, name) match
        case Left(reason) => refuse(spelling, reason)
        case Right(manifestNamed) if ImagePluginNames.contains(manifestNamed) =>
          refuse(
            spelling,
            s"its $ManifestFile names it $manifestNamed, a plugin of the image's, which a host plugin of that name " +
              "would displace",
          )
        case Right(manifestNamed) =>
          notItsOwn(directory) match
            case Some(reason) => refuse(spelling, reason)
            case None if !containerReadable(directory) =>
              refuse(
                spelling,
                "the directory's SELinux context does not allow container reads; " +
                  s"label it on the host first: chcon -R -t container_file_t -l s0 $directory",
              )
            case None => Right(Resolved(Plugin(name, directory), manifestNamed))
    def one(spelling: String): Either[String, Resolved] =
      realPath(Path.of(spelling)) match
        case None => refuse(spelling, "there is no such directory")
        case Some(directory) if !Files.isDirectory(directory) => refuse(spelling, "not a directory")
        case Some(directory) if !Files.isRegularFile(directory.resolve(ManifestFile)) =>
          refuse(spelling, s"not a Claude Code plugin directory: it has no $ManifestFile")
        case Some(directory) =>
          roots.find(root => overlapsInAnySpelling(os, directory, root.directory)) match
            case Some(root) =>
              refuse(spelling, s"it holds or is inside ${root.what}; keep plugins the session runs outside it")
            case None => named(spelling, directory)
    spelled.foldLeft[Either[String, Vector[Resolved]]](Right(Vector.empty)): (acc, spelling) =>
      acc.flatMap: plugins =>
        one(spelling).flatMap: resolved =>
          val name = resolved.plugin.name
          plugins.find(_.plugin.name == name) match
            case Some(other) =>
              refuse(spelling, s"a second plugin named $name; the first is ${other.plugin.directory}")
            case None =>
              plugins.find(_.manifestName == resolved.manifestName) match
                case Some(other) =>
                  refuse(
                    spelling,
                    s"a second plugin whose $ManifestFile names it ${resolved.manifestName}; the first is " +
                      s"${other.plugin.directory}, and Claude Code would load one hooks module of the two",
                  )
                case None => Right(plugins :+ resolved)
    .map(_.map(_.plugin))

  /** The name the manifest gives the plugin, or the directory's where it gives none. */
  private def manifestName(directory: Path, name: String): Either[String, String] =
    val manifest = directory.resolve(ManifestFile)
    val text =
      try Right(Files.readString(manifest))
      catch case ex: IOException => Left(s"its $ManifestFile cannot be read: ${ex.getMessage}")
    text.flatMap(JsonText.parse(_).left.map(reason => s"its $ManifestFile is $reason")).flatMap:
      case json @ JsonText.Json.Obj(_) =>
        json.field("name") match
          case None                           => Right(name)
          case Some(JsonText.Json.Str(value)) => Right(value)
          case Some(_)                        => Left(s"its $ManifestFile gives a name that is not a string")
      case _ => Left(s"its $ManifestFile is not a JSON object")

  /**
   * Why the tree under `directory` is not the plugin's alone, if it is not: the first symlink, the
   * first file with a second name, or the first whose names the host cannot count. The directory
   * itself is not examined.
   */
  private def notItsOwn(directory: Path): Option[String] =
    try
      val stream = Files.walk(directory)
      try
        stream.iterator().asScala.drop(1).map: entry =>
          if Files.isSymbolicLink(entry) then
            Some(s"$entry is a symlink, and a plugin the session runs must not lead outside its directory")
          else if Files.readAttributes(entry, classOf[BasicFileAttributes], LinkOption.NOFOLLOW_LINKS).isOther then
            Some(
              s"$entry is a junction, device or pipe, and a plugin the session runs holds files and directories alone",
            )
          else
            hasSecondName(entry) match
              case Some(false) => None
              case Some(true) =>
                Some(s"$entry has a second name (a hard link), through which a write would change it in place")
              case None => Some(s"whether $entry has a second name (a hard link) cannot be read on this host")
        .collectFirst { case Some(reason) => reason }
      finally stream.close()
    catch case ex: (IOException | UncheckedIOException) => Some(s"$directory cannot be walked: ${ex.getMessage}")

  /** The marketplace manifest listing the plugins, each by its directory under the marketplace root. */
  def marketplaceText(plugins: Vector[Plugin]): String =
    val entries = plugins.map: plugin =>
      s"""    { "name": ${quoted(plugin.name)}, "source": ${quoted("./" + plugin.name)} }"""
    s"""{
       |  "name": ${quoted(MarketplaceName)},
       |  "owner": { "name": "the host" },
       |  "plugins": [
       |${entries.mkString(",\n")}
       |  ]
       |}
       |""".stripMargin

  /**
   * The managed drop-in: the marketplace, each plugin enabled, and the order the plugins run
   * their mods in, the one spelling, ahead of the built-in guard, which a `prependPlugins` list must
   * name to keep. Only these keys, so what the option can set in managed settings is this.
   */
  def dropInText(plugins: Vector[Plugin]): String =
    val enabled = plugins.map(plugin => s"    ${quoted(plugin.id)}: true")
    val order = (plugins.map(_.id) :+ "sec-default@builtin").map(quoted)
    s"""{
       |  "extraKnownMarketplaces": {
       |    ${quoted(MarketplaceName)}: { "source": { "source": "directory", "path": ${quoted(MountRoot)} } }
       |  },
       |  "enabledPlugins": {
       |${enabled.mkString(",\n")}
       |  },
       |  "prependPlugins": [${order.mkString(", ")}]
       |}
       |""".stripMargin

  /**
   * The sandbox's `--volume` words: the generated marketplace root, relabeled like every launcher
   * file; each plugin's directory under it, never relabeled, being the user's (resolve has what
   * an enforcing host needs instead); and the drop-in. Podman mounts a destination's parent
   * before the destination, whatever the order here.
   */
  def mountArgs(
    marketplaceRoot: Path,
    dropIn: Path,
    plugins: Vector[Plugin],
    selinuxEnforcing: Boolean,
  ): Vector[String] =
    if plugins.isEmpty then Vector.empty
    else
      fileBind(marketplaceRoot, MountRoot, "ro", selinuxEnforcing)
        +: plugins.map(plugin => s"--volume=${plugin.directory}:${plugin.mountPath}:ro")
        :+ fileBind(dropIn, DropInPath, "ro", selinuxEnforcing)

  /** What the launch says: the plugins run under managed status, hooks and mods included. */
  def bannerLine(plugins: Vector[Plugin]): String =
    s"claude plugins: ${plugins.map(_.id).mkString(", ")}; their hooks and mods run as managed"

  private def quoted(text: String): String =
    val escaped = text.flatMap:
      case '"'            => "\\\""
      case '\\'           => "\\\\"
      case ch if ch < ' ' => f"\\u${ch.toInt}%04x"
      case ch             => ch.toString
    "\"" + escaped + "\""
