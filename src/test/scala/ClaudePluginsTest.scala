// --claude-plugin-dir: what a plugin directory must be to be mounted, and what the sandbox's Claude
// Code is told about it.

package agentsandbox.launcher

import java.nio.file.{Files, FileSystems, Path}
import java.nio.file.attribute.PosixFilePermission

import ClaudePlugins.*
import HostCommands.Os

class ClaudePluginsTest extends munit.FunSuite:

  private def plugin(root: Path, name: String, manifest: Option[String] = None): Path =
    val directory = root.resolve(name)
    Files.createDirectories(directory.resolve(".claude-plugin"))
    Files.writeString(directory.resolve(ManifestFile), manifest.getOrElse(s"""{ "name": "$name" }"""))
    Files.createDirectories(directory.resolve("hooks"))
    Files.writeString(directory.resolve("hooks/hooks.json"), """{ "modules": ["./register.ts"] }""")
    Files.writeString(directory.resolve("hooks/register.ts"), "export const register = () => {}\n")
    directory

  private def workspaceWritten(workspace: Path): SessionWritten =
    SessionWritten(workspace, "the workspace, which the session writes")

  private def resolved(spelled: Vector[String], workspace: Path, readable: Boolean = true, os: Os = Os.Linux) =
    resolve(spelled, Vector(workspaceWritten(workspace)), os, _ => readable)

  test("a plugin directory is named after its directory and bound where it is"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val band = plugin(root, "status-band")
    assertEquals(resolved(Vector(band.toString), workspace), Right(Vector(Plugin("status-band", band))))
    assertEquals(Plugin("status-band", band).id, "status-band@host")
    assertEquals(Plugin("status-band", band).mountPath, "/etc/claude-code/host-plugins/status-band")
    // Given through a link or with a trailing part, the real directory is what is mounted.
    assertEquals(resolved(Vector(s"$band/."), workspace), Right(Vector(Plugin("status-band", band))))

  test("a directory that is not a plugin, a bad name, a duplicate and an image plugin's name are refused"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    def refusal(spelled: String*): String = resolved(spelled.toVector, workspace).swap.getOrElse("accepted")
    assert(refusal(root.resolve("missing").toString).contains("no such directory"))
    val file = Files.writeString(root.resolve("file"), "")
    assert(refusal(file.toString).contains("not a directory"))
    val bare = Files.createDirectories(root.resolve("bare"))
    assert(refusal(bare.toString).contains("no .claude-plugin/plugin.json"))
    val spaced = plugin(root, "my plugin")
    assert(refusal(spaced.toString).contains("not a plugin id"))
    val image = plugin(root, "ko-review")
    assert(refusal(image.toString).contains("plugin of the image's"))
    val band = plugin(root, "status-band")
    val other = plugin(Files.createDirectories(root.resolve("other")), "status-band")
    val twice = refusal(band.toString, other.toString)
    assert(twice.contains("second plugin named status-band") && twice.contains(band.toString), twice)
    // Each refusal names the option as spelled.
    assert(refusal(bare.toString).startsWith(s"error: $OptionName=$bare; "))

  test("a plugin inside a directory the session or its host commands write, or holding one, is refused"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val band = plugin(root, "band")
    val inside = plugin(workspace.resolve("mods"), "inside")
    assert(resolved(Vector(inside.toString), workspace).swap.exists(_.contains("inside the workspace")))
    // The workspace given through a link is still the workspace.
    val link = Files.createSymbolicLink(root.resolve("workspace-link"), workspace)
    assert(resolved(Vector(inside.toString), link).swap.exists(_.contains("inside the workspace")))
    // A workspace inside the plugin: the session would write the plugin's hooks through the workspace.
    val holder = plugin(root, "holder")
    val refused = resolved(Vector(holder.toString), holder.resolve("hooks")).swap.getOrElse("accepted")
    assert(refused.contains("holds or is inside the workspace"), refused)
    // A directory --run-on-host commands write, named by the launch: the refusal names it as given.
    val cache = Files.createDirectories(root.resolve("cache"))
    val cached = plugin(cache.resolve("run-on-host"), "cached")
    val written = Vector(workspaceWritten(workspace), SessionWritten(cache, "the launcher's cache directory"))
    val cacheRefusal = resolve(Vector(cached.toString), written, Os.Linux, _ => true).swap.getOrElse("accepted")
    assert(cacheRefusal.contains("holds or is inside the launcher's cache directory"), cacheRefusal)
    assertEquals(resolve(Vector(band.toString), written, Os.Linux, _ => true).map(_.map(_.name)), Right(Vector("band")))
    // The comparison resolve makes, on the two spellings macOS gives one directory, tested on
    // literal paths: a real path keeps the spelling it was given, so a temporary directory cannot
    // stand in for the aliased one.
    val aliased = Path.of("/System/Volumes/Data/Users/me/workspace/mods/x")
    assert(SandboxWorkspace.overlapsInAnySpelling(Os.Mac, aliased, Path.of("/Users/me/workspace")))
    val aliasedWorkspace = Path.of("/System/Volumes/Data/Users/me/workspace")
    assert(SandboxWorkspace.overlapsInAnySpelling(Os.Mac, Path.of("/Users/me/workspace/mods/x"), aliasedWorkspace))
    assert(!SandboxWorkspace.overlapsInAnySpelling(Os.Linux, aliased, Path.of("/Users/me/workspace")))

  test("a cache a symlink redirects out of the cache root is a directory host commands write"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val cacheRoot = Files.createDirectories(root.resolve("cache"))
    val external = Files.createDirectories(root.resolve("build-cache"))
    // The runner follows a symlink at the cache, and one at the workspace's directory (run-on-host/<id>).
    val workspaceCaches = Files.createDirectories(RunOnHostPrereqs.runOnHostCachesOf(cacheRoot).resolve("p1"))
    Files.createSymbolicLink(workspaceCaches.resolve("ivy-home"), external)
    Files.createSymbolicLink(RunOnHostPrereqs.runOnHostCachesOf(cacheRoot).resolve("p2"), root.resolve("elsewhere"))
    Files.createDirectories(root.resolve("elsewhere"))
    val written = RunOnHostPrereqs.writtenCacheDirectories(cacheRoot).getOrElse(Vector.empty)
    assert(written.contains(external), written)
    assert(written.contains(root.resolve("elsewhere/sbt-global")), written)
    assert(written.contains(RunOnHostPrereqs.coursierV1Of(cacheRoot, "p1")), written)
    val band = plugin(external, "band")
    val roots = workspaceWritten(workspace) +: written.map(SessionWritten(_, "a --run-on-host cache"))
    val refused = resolve(Vector(band.toString), roots, Os.Linux, _ => true).swap.getOrElse("accepted")
    assert(refused.contains("holds or is inside a --run-on-host cache"), refused)
    // No tree yet: no caches. A tree that cannot be listed, or a file in its place: unknown, the Left.
    assertEquals(RunOnHostPrereqs.writtenCacheDirectories(root.resolve("fresh")), Right(Vector.empty))
    val blocked = Files.createDirectories(root.resolve("blocked"))
    Files.writeString(RunOnHostPrereqs.runOnHostCachesOf(blocked), "")
    assert(RunOnHostPrereqs.writtenCacheDirectories(blocked).swap.exists(_.contains("cannot be listed")))

  test("a cache tree this user cannot list leaves the caches unknown"):
    assume(FileSystems.getDefault.supportedFileAttributeViews.contains("posix"), "no POSIX permissions here")
    val cacheRoot = Files.createTempDirectory("claude-plugins").toRealPath()
    val tree = Files.createDirectories(RunOnHostPrereqs.runOnHostCachesOf(cacheRoot))
    val listable = Files.getPosixFilePermissions(tree)
    try
      val unlistable = java.util.EnumSet.of(PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
      Files.setPosixFilePermissions(tree, unlistable)
      assume(!Files.isReadable(tree), "this user reads the directory whatever its mode")
      val unlisted = RunOnHostPrereqs.writtenCacheDirectories(cacheRoot)
      assert(unlisted.swap.exists(_.contains("cannot be listed")), unlisted)
    finally Files.setPosixFilePermissions(tree, listable)

  test("a plugin holding a symlink, a hard-linked file or a pipe, and one the container cannot read, are refused"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    val linked = plugin(root, "linked")
    Files.createSymbolicLink(linked.resolve("hooks/shared"), workspace)
    val refused = resolved(Vector(linked.toString), workspace).swap.getOrElse("accepted")
    assert(refused.contains("symlink") && refused.contains("hooks/shared"), refused)
    // A file the workspace also names: a session write through the workspace's name changes the module.
    val shared = plugin(root, "shared")
    Files.createLink(workspace.resolve("register-source.ts"), shared.resolve("hooks/register.ts"))
    val linkRefusal = resolved(Vector(shared.toString), workspace).swap.getOrElse("accepted")
    assert(linkRefusal.contains("second name") && linkRefusal.contains("hooks/register.ts"), linkRefusal)
    // Neither a file nor a directory: a pipe here, the stand-in for a Windows junction, which Java
    // reports as a directory and as `isOther`, never as a symlink.
    val piped = plugin(root, "piped")
    val pipe = piped.resolve("hooks/pipe")
    val made =
      try ProcessBuilder("mkfifo", pipe.toString).inheritIO().start().waitFor() == 0
      catch case _: java.io.IOException => false
    assume(made, "mkfifo is not available")
    val pipeRefusal = resolved(Vector(piped.toString), workspace).swap.getOrElse("accepted")
    assert(pipeRefusal.contains("junction, device or pipe") && pipeRefusal.contains("hooks/pipe"), pipeRefusal)
    val band = plugin(root, "status-band")
    val relabel = resolved(Vector(band.toString), workspace, readable = false).swap.getOrElse("accepted")
    assert(relabel.contains("chcon -R -t container_file_t -l s0"), relabel)

  test("the manifest's name is read: not JSON, an image plugin's name, and a name two plugins share are refused"):
    val root = Files.createTempDirectory("claude-plugins").toRealPath()
    val workspace = Files.createDirectories(root.resolve("workspace"))
    def refusal(spelled: String*): String = resolved(spelled.toVector, workspace).swap.getOrElse("accepted")
    val broken = plugin(root, "broken", Some("""{ "name": "broken", }"""))
    assert(refusal(broken.toString).contains("plugin.json is not JSON at offset"), refusal(broken.toString))
    val numbered = plugin(root, "numbered", Some("""{ "name": 3 }"""))
    assert(refusal(numbered.toString).contains("name that is not a string"))
    val review = plugin(root, "my-review", Some("""{ "author": { "name": "me" }, "name": "ko-review" }"""))
    assert(refusal(review.toString).contains("names it ko-review, a plugin of the image's"), refusal(review.toString))
    // A repeated key names the plugin by its last value, as Claude Code reads it.
    val repeated = plugin(root, "repeated", Some("""{ "name": "safe", "name": "ko-review" }"""))
    assert(refusal(repeated.toString).contains("names it ko-review"), refusal(repeated.toString))
    val first = plugin(root, "band-a", Some("""{ "name": "band" }"""))
    val second = plugin(root, "band-b", Some("""{ "name": "band" }"""))
    val twice = refusal(first.toString, second.toString)
    assert(twice.contains("names it band") && twice.contains(first.toString), twice)
    // A manifest without a name, and one whose name differs from the directory's, are plugins
    // named after their directories; the manifest name counts only for the conflicts above.
    val unnamed = plugin(root, "unnamed", Some("""{ "version": "1.0.0" }"""))
    assertEquals(
      resolved(Vector(unnamed.toString, first.toString), workspace),
      Right(Vector(Plugin("unnamed", unnamed), Plugin("band-a", first))),
    )

  test("the marketplace lists each plugin by its directory, and the drop-in names only the marketplace keys"):
    val plugins = Vector(Plugin("questions", Path.of("/h/questions")), Plugin("status-band", Path.of("/h/status-band")))
    assertEquals(
      marketplaceText(plugins),
      """{
        |  "name": "host",
        |  "owner": { "name": "the host" },
        |  "plugins": [
        |    { "name": "questions", "source": "./questions" },
        |    { "name": "status-band", "source": "./status-band" }
        |  ]
        |}
        |""".stripMargin,
    )
    assertEquals(
      dropInText(plugins),
      """{
        |  "extraKnownMarketplaces": {
        |    "host": { "source": { "source": "directory", "path": "/etc/claude-code/host-plugins" } }
        |  },
        |  "enabledPlugins": {
        |    "questions@host": true,
        |    "status-band@host": true
        |  },
        |  "prependPlugins": ["questions@host", "status-band@host", "sec-default@builtin"]
        |}
        |""".stripMargin,
    )

  test("the mounts: the generated root and drop-in relabeled on an enforcing host, the user's directories never"):
    val plugins = Vector(Plugin("status-band", Path.of("/h/status-band")))
    assertEquals(
      mountArgs(Path.of("/run/claude-plugins"), Path.of("/run/50-host-plugins.json"), plugins, selinuxEnforcing = true),
      Vector(
        "--volume=/run/claude-plugins:/etc/claude-code/host-plugins:ro,Z",
        "--volume=/h/status-band:/etc/claude-code/host-plugins/status-band:ro",
        "--volume=/run/50-host-plugins.json:/etc/claude-code/managed-settings.d/50-host-plugins.json:ro,Z",
      ),
    )
    assertEquals(
      mountArgs(Path.of("/run/claude-plugins"), Path.of("/run/50-host-plugins.json"), plugins, selinuxEnforcing = false)
        .map(_.split(':').last),
      Vector("ro", "ro", "ro"),
    )
    assertEquals(mountArgs(Path.of("/run/x"), Path.of("/run/y"), Vector.empty, selinuxEnforcing = true), Vector.empty)
    assertEquals(bannerLine(plugins), "claude plugins: status-band@host; their hooks and mods run as managed")

  test("the image plugin names are the Containerfile's plugin directories, and their manifests' names"):
    val directories = FileHelper.directoryEntries(Path.of("container/ko-agent-sandbox/claude-code/plugins"))
      .filter(Files.isDirectory(_))
    assertEquals(directories.map(_.getFileName.toString).sorted, ImagePluginNames.sorted)
    // One list covers both names Claude Code compares: the id's name part and the manifest's.
    directories.foreach: directory =>
      val manifest = JsonText.parse(Files.readString(directory.resolve(ManifestFile))).toOption.get
      assertEquals(manifest.field("name"), Some(JsonText.Json.Str(directory.getFileName.toString)))

  test("the probe plugin under src/test is a --claude-plugin-dir operand from any other workspace"):
    val workspace = Files.createTempDirectory("workspace").toRealPath()
    val probe = Path.of(ProbePlugin).toRealPath()
    assertEquals(resolved(Vector(ProbePlugin), workspace), Right(Vector(Plugin("managed-probe", probe))))
