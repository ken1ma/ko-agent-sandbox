package koreview

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*
import HelperFixture.*

/** A turn's start rebuilt from the patches: the bytes on disk at the turn's start, whatever the user's Git
  * configuration says, without the paths that the patches leave out. */
class PatchesTest extends HelperFixture:
  def reviewer = "codex"

  private def restore(id: String, turn: Int): (Path, Vector[String]) =
    val directory = root.resolve(s"restored-$id-$turn-${System.nanoTime()}")
    val output = helper("restore", id, "--turn", turn.toString, directory.toString)
    (directory, output.strings("leftOutPaths"))

  private def files(directory: Path): Map[String, Seq[Byte]] =
    Files.walk(directory).iterator().asScala.filter(path => Files.isRegularFile(path) && !Files.isSymbolicLink(path))
      .map(path => directory.relativize(path).toString -> Files.readAllBytes(path).toSeq).toMap

  private def onDisk(paths: String*): Map[String, Seq[Byte]] =
    paths.map(path => path -> Files.readAllBytes(repo.resolve(path)).toSeq).toMap

  test("a rebuilt start holds the bytes on disk, which a later line-ending attribute does not change"):
    write(".gitattributes", "*.txt text eol=crlf\n")
    write("f.txt", "one\ntwo\n")
    git("add", "-A")
    git("commit", "-q", "-m", "converted at checkout")
    Files.delete(repo.resolve("f.txt"))
    git("checkout", "--", "f.txt") // the checkout writes CRLF; the blob holds LF
    assertEquals(Files.readString(repo.resolve("f.txt")), "one\r\ntwo\r\n")
    write("work.py", "print('more work')\n")
    val id = start().str("reviewId")
    val patch = Files.readString(turnDir(id, 1).resolve("start.patch"))
    assert(patch.contains("f.txt"), "the first patch holds a file whose bytes on disk differ from its blob")
    val (first, _) = restore(id, 1)
    assertEquals(files(first).filter(_._1.endsWith(".txt")), onDisk("f.txt"))
    Files.writeString(repo.resolve(".git/info/attributes"), "*.txt text eol=lf\n")
    val (again, _) = restore(id, 1)
    assertEquals(files(again), files(first))

  test("the user's Git configuration does not shape what a patch stores or a rebuild writes"):
    val home = Files.createDirectory(root.resolve("home"))
    Files.writeString(home.resolve(".gitconfig"), "[diff]\n\tnoprefix = true\n\tmnemonicPrefix = true\n")
    environment = Map("HOME" -> home.toString, "XDG_CONFIG_HOME" -> home.resolve(".config").toString)
    git("config", "diff.external", "false")
    git("config", "diff.upper.textconv", "tr a-z A-Z")
    git("config", "apply.whitespace", "fix")
    git("config", "core.autocrlf", "true")
    Files.writeString(repo.resolve(".git/info/attributes"), "*.py diff=upper\n")
    write("app.py", "print('trailing')   \n\tindented after a tab\n")
    val id = start().str("reviewId")
    val patch = Files.readString(turnDir(id, 1).resolve("start.patch"))
    assert(patch.contains("print('trailing')   "), patch) // as written, neither textconv'd nor stripped
    assert(patch.contains("--- a/old/app.py"), patch)
    val (first, _) = restore(id, 1)
    assertEquals(files(first).filter(_._1.endsWith(".py")), onDisk("app.py", "work.py"))
    val (status, out, err) = helperStreams(Seq("diff", id))
    assertEquals((status, out, err), (0, "", ""), "the files are the turn's start")
    environment = Map.empty

  test("a binary file that changes is left out of a rebuild, and diff names it"):
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 1, 2, 3))
    git("add", "-A")
    git("commit", "-q", "-m", "binary")
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 9, 9, 9))
    val id = start().str("reviewId")
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 7, 7, 7))
    write("app.py", "print('second')\n")
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    for turn <- Seq(1, 2) do
      val (directory, leftOut) = restore(id, turn)
      assertEquals(leftOut, Vector("data.bin"))
      assert(!Files.exists(directory.resolve("data.bin")))
    val (status, out, err) = helperStreams(Seq("diff", id, "--from", "1", "--to", "2", "--", "--name-only"))
    assertEquals(status, 0, err)
    assertEquals(out.linesIterator.toVector, Vector("app.py"))
    assert(err.contains("the review keeps no copy of their content: data.bin"), err)
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 1, 2, 3))
    write("data.bin", "text again\n") // a binary file that becomes text is whole in the next patch
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    val (third, leftOut) = restore(id, 3)
    assertEquals(leftOut, Vector.empty)
    assertEquals(Files.readString(third.resolve("data.bin")), "text again\n")

  test("symlinks, executable bits, deletions and untracked files survive a rebuild"):
    write("gone.txt", "deleted later\n")
    git("add", "-A")
    git("commit", "-q", "-m", "a file to delete")
    Files.createSymbolicLink(repo.resolve("link"), Path.of("app.py"))
    write("script.sh", "#!/bin/sh\necho one\n").toFile.setExecutable(true)
    Files.delete(repo.resolve("gone.txt"))
    val id = start().str("reviewId")
    write("script.sh", "#!/bin/sh\necho two\n")
    Files.delete(repo.resolve("link"))
    Files.createSymbolicLink(repo.resolve("link"), Path.of("work.py"))
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    val (first, _) = restore(id, 1)
    assertEquals(Files.readSymbolicLink(first.resolve("link")), Path.of("app.py"))
    assert(Files.isExecutable(first.resolve("script.sh")))
    assertEquals(Files.readString(first.resolve("script.sh")), "#!/bin/sh\necho one\n")
    assert(!Files.exists(first.resolve("gone.txt")))
    val (second, _) = restore(id, 2)
    assertEquals(Files.readSymbolicLink(second.resolve("link")), Path.of("work.py"))
    assert(Files.isExecutable(second.resolve("script.sh")))
    assertEquals(files(second), files(first) + ("script.sh" -> "#!/bin/sh\necho two\n".getBytes.toSeq))
    val (status, out, _) = helperStreams(Seq("diff", id, "--from", "1", "--to", "2", "--", "--name-status"))
    assertEquals(status, 0)
    assertEquals(out.linesIterator.toVector.sorted, Vector("M\tlink", "M\tscript.sh"))
    assertEquals(error("restore", id, "--turn", "2", first.toString).str("code"), "DIRECTORY_NOT_EMPTY")
    assertEquals(error("restore", id, "--turn", "3", root.resolve("none").toString).str("code"), "UNKNOWN_TURN")

  test("a symlink's target is kept byte for byte, trailing slashes and bytes that are not UTF-8 included"):
    Files.createDirectories(repo.resolve("dir"))
    write("dir/inside.txt", "inside\n")
    Files.createSymbolicLink(repo.resolve("slashed"), Path.of("dir"))
    HelperFixture.run(repo, Map.empty, Seq("sh", "-c", "rm slashed && ln -s dir/ slashed"))
    git("add", "-A")
    git("commit", "-q", "-m", "a link whose target ends in a slash")
    write("work.py", "print('more work')\n")
    if Posix.isLinux then // macOS refuses such a target
      HelperFixture.run(repo, Map.empty, Seq("sh", "-c", "ln -s \"$(printf '\\377')\" odd"))
    val id = start(Approved).str("reviewId")
    val (first, _) = restore(id, 1)
    assertEquals(String(Posix.readlink(first.resolve("slashed")), java.nio.charset.StandardCharsets.UTF_8), "dir/")
    if Posix.isLinux then
      assertEquals(Posix.readlink(first.resolve("odd")).toSeq, Seq(0xff.toByte))
      // a target that differs only in bytes that are not UTF-8 is a change
      HelperFixture.run(repo, Map.empty, Seq("sh", "-c", "rm odd && ln -s \"$(printf '\\376')\" odd"))
      assertEquals(error("check-approval", id).arr("staleReasons").head.asObject.get.strings("paths"), Vector("odd"))

  test("a file that becomes part of a nested repository, or leaves one, keeps its representable side"):
    write("vendor/file.txt", "committed\n")
    git("add", "-A")
    git("commit", "-q", "-m", "vendored file")
    git("rm", "-q", "-r", "--cached", "vendor")
    gitIn(repo.resolve("vendor"), "init", "-q") // vendor/file.txt now belongs to a nested repository
    val id = start().str("reviewId")
    val (first, leftOut) = restore(id, 1)
    assertEquals(leftOut, Vector("vendor"))
    assert(!Files.exists(first.resolve("vendor/file.txt")), "the file left the superproject's files")
    deleteTree(repo.resolve("vendor/.git")) // vendor/file.txt is an ordinary untracked file again
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    val (second, secondLeftOut) = restore(id, 2)
    assertEquals(secondLeftOut, Vector.empty)
    assertEquals(Files.readString(second.resolve("vendor/file.txt")), "committed\n")

  test("a path that changes between a file and a nested repository keeps its representable side"):
    write("lib", "a regular file\n")
    git("add", "-A")
    git("commit", "-q", "-m", "a file that becomes a repository")
    Files.delete(repo.resolve("lib"))
    Files.createDirectory(repo.resolve("lib"))
    gitIn(repo.resolve("lib"), "init", "-q")
    Files.writeString(repo.resolve("lib/inner.txt"), "inside\n")
    val id = start().str("reviewId")
    val (first, leftOut) = restore(id, 1)
    assertEquals(leftOut, Vector("lib"))
    assert(!Files.exists(first.resolve("lib")), "the committed file is gone from the start")
    deleteTree(repo.resolve("lib"))
    write("lib", "a regular file again\n")
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    val (second, secondLeftOut) = restore(id, 2)
    assertEquals(secondLeftOut, Vector.empty)
    assertEquals(Files.readString(second.resolve("lib")), "a regular file again\n")
    val (status, out, err) = helperStreams(Seq("diff", id, "--from", "1", "--to", "2", "--", "--name-status"))
    assertEquals(status, 0, err)
    assertEquals(out.linesIterator.toVector, Vector("A\tlib"))
    assert(err.contains("the review keeps no copy of their content: lib"), err)

  private def onNoexecMount(body: Path => Unit): Unit =
    val mount = Path.of("/dev/shm")
    assume(Posix.isLinux && Files.isWritable(mount), "needs a writable Linux noexec mount")
    val directory = Files.createTempDirectory(mount, "ko-review-mode-")
    try
      val probe = Files.writeString(directory.resolve("probe"), "probe\n")
      probe.toFile.setExecutable(true)
      assume(!Files.isExecutable(probe), "the mount must be noexec")
      Files.delete(probe)
      body(directory)
    finally deleteTree(directory)

  test("executable modes survive copying across a noexec mount"):
    onNoexecMount: noexec =>
      val file = write("script.sh", "#!/bin/sh\necho one\n")
      file.toFile.setExecutable(true)
      assume(Files.isExecutable(file), "the source mount must allow execution")
      val git = Git(Path.of("/usr/bin/git"), env)
      val before = Observation.observe(git, repo)
      Patches.copyCurrent(git, repo, "script.sh", before, noexec)
      assertEquals(Observation.entry(git, noexec.resolve("script.sh")).map(_._2.toSeq),
        Observation.entry(git, file).map(_._2.toSeq))

  test("an unchanged executable on noexec needs no patch"):
    onNoexecMount: noexec =>
      val source = Files.createDirectory(noexec.resolve("repo"))
      gitIn(source, "init", "-q")
      val file = Files.writeString(source.resolve("script.sh"), "#!/bin/sh\necho one\n")
      file.toFile.setExecutable(true)
      gitIn(source, "add", "script.sh")
      gitIn(source, "commit", "-q", "-m", "executable on noexec")
      val git = Git(Path.of("/usr/bin/git"), env)
      val observation = Observation.observe(git, source)
      val patch = root.resolve("mode.patch")
      Patches.write(git, source, Chain(observation.head, Vector.empty), None, observation, patch)
      assertEquals(Files.readString(patch), "", "the mode on disk equals the committed mode")

  test("diff preserves bytes despite rebuilt attributes"):
    val attributes = "*.txt text=auto\n*.id ident\n*.enc working-tree-encoding=ISO-8859-1\n"
    write(".gitattributes", attributes)
    write("f.txt", "one\r\n")
    write("f.id", "$Id: first $\n")
    Files.write(repo.resolve("f.enc"), Array(0xe9.toByte, '\n'.toByte))
    val id = start().str("reviewId")
    write(".gitattributes", attributes + "# another version\n")
    write("f.txt", "one\n")
    write("f.id", "$Id: second $\n")
    write("f.enc", "é\n")
    def compared(options: String*): Unit =
      val (status, out, err) = helperStreams(Seq("diff", id) ++ options ++ Seq("--", "--name-only"))
      assertEquals(status, 0, err)
      assertEquals(out.linesIterator.toVector.sorted, Vector(".gitattributes", "f.enc", "f.id", "f.txt"))
      val (_, raw, _) = helperStreams(Seq("diff", id) ++ options ++ Seq("--", "--raw"))
      val oid = git("hash-object", "--no-filters", "f.enc").trim.take(7)
      assert(raw.contains(s" $oid M\tf.enc"), raw)
    compared()
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    compared("--from", "1", "--to", "2")

  test("restore excludes deleted binary files from missing content"):
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 1))
    val id = start().str("reviewId")
    Files.delete(repo.resolve("data.bin"))
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    val (directory, leftOut) = restore(id, 2)
    assertEquals(leftOut, Vector.empty)
    assert(!Files.exists(directory.resolve("data.bin")))

  test("diff shows text added after a binary file was deleted"):
    Files.write(repo.resolve("data.bin"), Array[Byte](0, 1))
    val id = start().str("reviewId")
    Files.delete(repo.resolve("data.bin"))
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    write("data.bin", "text\n")
    def compared(options: String*): Unit =
      val (status, out, err) = helperStreams(Seq("diff", id, "--from", "2") ++ options ++ Seq("--", "--name-status"))
      assertEquals((status, out.trim, err), (0, "A\tdata.bin", ""))
    compared()
    plan(step("result" -> Approved))
    helper("continue", id, "--message-file", message())
    compared("--to", "3")
