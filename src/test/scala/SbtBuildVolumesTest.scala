// Tests which sbt builds a launch gives a project/target volume of their own. A build the walk misses shares its
// server address file with the host, and a volume over a symlink would cover whatever the link names.

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import FileHelper.deleteRecursively
import FileRules.{Line, Word}
import HostCommands.Os

class SbtBuildVolumesTest extends munit.FunSuite:

  private val isWindows = System.getProperty("os.name").toLowerCase.contains("win")
  private val os = if isWindows then Os.Windows else Os.Linux

  private val workspace = FunFixture[Path](
    setup = _ => Files.createTempDirectory("sbt-build-volumes").toRealPath(),
    teardown = deleteRecursively,
  )

  private def touch(root: Path, relative: String): Unit =
    val file = root.resolve(relative)
    Files.createDirectories(file.getParent)
    Files.writeString(file, "")

  private def targetOf(root: Path, relative: String): Path = root.resolve(relative).resolve("project/target").normalize

  private def mountOf(root: Path, relative: String): String =
    SandboxWorkspace.mountPathOf(os, targetOf(root, relative)).fold(fail(_), identity)

  private def skippedNames(planned: SbtBuildVolumes.Planned): Vector[String] =
    planned.skipped.map(_._1.getFileName.toString).sorted

  private def targets(planned: SbtBuildVolumes.Planned): Vector[Path] = planned.targets.map(_.target)

  workspace.test("a build.sbt or a project/build.properties makes a build at any depth, outside the pruned names"):
    root =>
      touch(root, "build.sbt")
      touch(root, "project/build.sbt") // the root build's own definition
      touch(root, "a/b/project/build.properties")
      touch(root, "c/build.sbt")
      touch(root, "c/project/plugins.sbt")
      touch(root, "settings/global.sbt") // a settings file alone is no build
      touch(root, "tools/sbt-test/build.sbt") // only src/sbt-test holds scripted tests
      Vector(".git", ".ko-agent-sandbox", "node_modules", "target", "c/target", "src/sbt-test/group").foreach:
        pruned => touch(root, s"$pruned/inner/build.sbt")
      val planned = SbtBuildVolumes.plan(root, Vector.empty, os)
      assertEquals(planned.skipped, Vector.empty)
      assertEquals(targets(planned), Vector(".", "c", "a/b", "tools/sbt-test").map(targetOf(root, _)))

  workspace.test("a directory named project is a build of its own unless it is an enclosing build's definition"):
    root =>
      touch(root, "examples/project/build.sbt")
      touch(root, "examples/project/project/build.properties")
      val planned = SbtBuildVolumes.plan(root, Vector.empty, os)
      assertEquals(targets(planned), Vector(targetOf(root, "examples/project")))
      val named = root.resolve("project")
      touch(named, "build.sbt")
      assertEquals(targets(SbtBuildVolumes.plan(named, Vector.empty, os)), Vector(targetOf(named, ".")))

  workspace.test("the plan writes nothing; prepare creates each missing project/target and keeps an existing one"):
    root =>
      touch(root, "fresh/build.sbt")
      touch(root, "used/build.sbt")
      touch(root, "used/project/target/active.json")
      val planned = SbtBuildVolumes.plan(root, Vector.empty, os)
      assert(!Files.exists(root.resolve("fresh/project")))
      val (mounts, changed) = SbtBuildVolumes.prepare(planned, os)
      assertEquals(changed, Vector.empty)
      assertEquals(mounts, Vector("fresh", "used").map(mountOf(root, _)))
      assert(Files.isDirectory(root.resolve("fresh/project/target")))
      assert(Files.isRegularFile(root.resolve("used/project/target/active.json")))

  workspace.test("a build whose project or project/target a read-only line covers is skipped, unless a line lifts it"):
    root =>
      touch(root, "vendor/lib/build.sbt")
      touch(root, "Tests/x/build.sbt") // case folds, and matches t*s
      touch(root, "tools/x/keep/build.sbt")
      touch(root, "meta/build.sbt") // `read-only project` then `writable project/target`: project would be created
      val lines = Vector(
        Line(Word.ReadOnly, "vendor"), Line(Word.ReadOnly, "t*s"), Line(Word.Writable, "keep"),
        Line(Word.ReadOnly, "project"), Line(Word.Writable, "project/target"),
      )
      val planned = SbtBuildVolumes.plan(root, lines, os)
      assertEquals(skippedNames(planned), Vector("keep", "lib", "meta", "x"))
      val warning = SbtBuildVolumes.skippedWarning(planned.skipped, os).getOrElse("")
      planned.skipped.foreach((root, _) => assert(warning.contains(root.getFileName.toString), warning))
      assert(!Files.exists(root.resolve("vendor/lib/project")))
      val lifted = SbtBuildVolumes.plan(root, Vector(Line(Word.ReadOnly, "tools"), Line(Word.Writable, "keep")), os)
      assert(targets(lifted).contains(targetOf(root, "tools/x/keep")))

  test("a rule line matches a component as the workspace policy folds it"):
    val lines = Vector(Line(Word.ReadOnly, ".vscode"))
    Vector(".vscode", ".VSCode", ".vscode.", ".vscode ", ".vs\u200bcode").foreach: spelled =>
      assert(FileRules.readOnlyByLines(Vector(spelled, "x"), lines), spelled)
    assert(!FileRules.readOnlyByLines(Vector("vscode", "x"), lines))
    assertEquals(FileRules.fold("\u212Aey\u017F"), "keys")

  workspace.test("a build behind a symlink is not entered, and a linked project or project/target is skipped"):
    root =>
      assume(!isWindows, "creating a symlink on Windows needs Developer Mode or elevation")
      touch(root, "real/build.sbt")
      Files.createSymbolicLink(root.resolve("alias"), root.resolve("real"))
      touch(root, "linked-project/build.sbt")
      Files.createDirectories(root.resolve("elsewhere/target"))
      Files.createSymbolicLink(root.resolve("linked-project/project"), root.resolve("elsewhere"))
      touch(root, "linked-target/build.sbt")
      Files.createDirectories(root.resolve("linked-target/project"))
      Files.createSymbolicLink(root.resolve("linked-target/project/target"), root.resolve("elsewhere/target"))
      val planned = SbtBuildVolumes.plan(root, Vector.empty, os)
      assertEquals(targets(planned), Vector(targetOf(root, "real")))
      assertEquals(skippedNames(planned), Vector("linked-project", "linked-target"))

  workspace.test("prepare creates nothing in a build that changed after the plan"):
    root =>
      assume(!isWindows, "creating a symlink on Windows needs Developer Mode or elevation")
      Vector("removed", "linked-project", "moved/inner").foreach(build => touch(root, s"$build/build.sbt"))
      val planned = SbtBuildVolumes.plan(root, Vector.empty, os)
      deleteRecursively(root.resolve("removed"))
      Files.createDirectories(root.resolve("elsewhere"))
      Files.createSymbolicLink(root.resolve("linked-project/project"), root.resolve("elsewhere"))
      Files.move(root.resolve("moved"), root.resolve("moved-away"))
      touch(root, "decoy/inner/build.sbt")
      Files.createSymbolicLink(root.resolve("moved"), root.resolve("decoy")) // an ancestor that became a symlink
      val (mounts, changed) = SbtBuildVolumes.prepare(planned, os)
      assertEquals(mounts, Vector.empty)
      assertEquals(changed.map(_._1).sorted, Vector("linked-project", "moved/inner", "removed").map(root.resolve))
      assert(!Files.exists(root.resolve("removed")))
      assert(!Files.exists(root.resolve("elsewhere/target")))
      assert(!Files.exists(root.resolve("decoy/inner/project")))

  workspace.test("a path holding a comma or a quote gets a volume"):
    root =>
      val names = Vector("a,b") ++ Option.unless(isWindows)("q\"uote")
      names.foreach(name => touch(root, s"$name/build.sbt"))
      assertEquals(targets(SbtBuildVolumes.plan(root, Vector.empty, os)).sorted, names.map(targetOf(root, _)).sorted)

  test("where the command line is capped, the volumes that fit the complete command are kept in order"):
    val command = Vector("podman", "create", "x" * 1000)
    val mounts = (1 to 1000).map(i => f"/w/modules/module-$i%04d/project/target").toVector
    assertEquals(SbtBuildVolumes.fitting(command, mounts, None), mounts)
    val fitted = SbtBuildVolumes.fitting(command, mounts, Some(SbtBuildVolumes.WindowsCommandLineLimit))
    assertEquals(fitted, mounts.take(fitted.size))
    // Each pair is `--volume` (8 characters) and a 37-character path, each with a separator and two quotes: 51. The
    // rest is 260 for the executable, 1 for the terminator, and 9 + 9 + 1003 for the other words.
    assertEquals(fitted.size, (32767 - 260 - 1 - 1021) / 51)

  test("a word's Windows cost counts the escapes Java's argument encoding may add"):
    // `a "b" c\` encodes as "a \"b\" c\\": the two quotes and the trailing backslash gain one character each.
    assertEquals(SbtBuildVolumes.windowsCost("a \"b\" c\\"), 8 + 3 + 3)

  test("each volume is a one-field --volume at the container path, which podman makes anonymous"):
    assertEquals(
      SbtBuildVolumes.arguments(Vector("/w/project/target", "/w/a,b/project/target")),
      Vector("--volume", "/w/project/target", "--volume", "/w/a,b/project/target"),
    )
