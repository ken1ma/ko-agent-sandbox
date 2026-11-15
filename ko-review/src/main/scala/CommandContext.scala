package koreview

import java.io.PrintStream
import java.nio.file.{Files, Path}

/** What a command runs in. The helper reads no environment variable or working directory, and writes no standard
  * stream, but these,
  * so that the tests run commands in one JVM.
  *
  * @param pluginRoot the plugin's directory, which holds prompts/ and schemas/
  * @param javaCommand the command that starts this JVM's classes, for `JoinGroup`
  */
final case class CommandContext(
    cwd: Path,
    env: Map[String, String],
    out: PrintStream,
    err: PrintStream,
    pluginRoot: Path,
    pluginVersion: Option[String],
    javaCommand: Seq[String],
):
  /** The executable named `program` on the PATH that `env` holds. A child that the JVM starts is found on the JVM's
    * own PATH, so the helper resolves programs itself. */
  def find(program: String): Option[Path] =
    env.getOrElse("PATH", "").split(java.io.File.pathSeparator).iterator.filter(_.nonEmpty)
      .map(Path.of(_, program)).find(path => Files.isRegularFile(path) && Files.isExecutable(path))

  def git: Git = Git(find("git").getOrElse(throw ReviewError("GIT_FAILED", "git is not on PATH")), env)

  def resolve(path: String): Path = cwd.resolve(path)
