// The launcher's own text is ASCII (design.md, "The launcher's text is ASCII"). The check reads the
// compiled classes rather than the sources: a comment never reaches them, and every literal does,
// the scripts the launcher embeds and the egress proxy's text included.

package agentsandbox.launcher

import scala.jdk.CollectionConverters.*
import scala.util.Using

import java.lang.classfile.ClassFile
import java.lang.classfile.constantpool.StringEntry
import java.nio.file.{Files, Paths}
import java.util.jar.JarFile

class AsciiTextTest extends munit.FunSuite:

  /** Each class file compiled from the launcher's sources, by name; sbt may expose that output as
    * a directory or a jar. */
  private def compiledClasses(): Vector[(String, Array[Byte])] =
    val built = Paths.get(AgentSandboxLauncher.getClass.getProtectionDomain.getCodeSource.getLocation.toURI)
    if Files.isDirectory(built) then
      Using.resource(Files.walk(built)): files =>
        files.iterator.asScala.filter(_.toString.endsWith(".class")).map: file =>
          built.relativize(file).iterator.asScala.mkString("/") -> Files.readAllBytes(file)
        .toVector
    else
      Using.resource(JarFile(built.toFile)): jar =>
        jar.entries.asScala.filter(_.getName.endsWith(".class")).map: entry =>
          entry.getName -> Using.resource(jar.getInputStream(entry))(_.readAllBytes())
        .toVector

  /** The non-ASCII sequences a class matches or writes into a script, which it never prints as
    * text; a constant is checked with them removed, the longer first. */
  private val Recognized: Map[String, Vector[String]] = Map(
    // PowerShell takes these for its quotes, so a path holding one is quoted and escaped.
    "agentsandbox/launcher/HostCommands$.class" -> Vector("\u201c\u201d\u201e", "\u2018\u2019\u201a\u201b"),
    // The byte-order mark a config file may begin with.
    "agentsandbox/launcher/SandboxWorkspace$.class" -> Vector("\uFEFF"),
    // AppleScript's syntax for the clipboard's PNG, in the relay's macOS commands.
    "agentsandbox/launcher/ClipboardRelay$.class" -> Vector("\u00abclass PNGf\u00bb", "\u00abdata PNGf", "\u00bb"),
  )

  private def escaped(text: String): String =
    text.flatMap(char => if char < 0x80 then char.toString else f"\\u${char.toInt}%04x")

  test("every string constant in the launcher's classes is ASCII"):
    val classes = compiledClasses()
    assert(classes.exists(_._1 == "agentsandbox/launcher/AgentSandboxLauncher$.class"), classes.map(_._1))
    val offending =
      for
        (name, bytes) <- classes
        constant <- ClassFile.of().parse(bytes).constantPool.iterator.asScala
        text <- Some(constant).collect { case string: StringEntry => string.stringValue }
        rest = Recognized.getOrElse(name, Vector.empty).foldLeft(text)(_.replace(_, ""))
        if rest.exists(_ >= 0x80)
      yield s"$name: ${escaped(text)}"
    assert(offending.isEmpty, offending.distinct.mkString("\n"))
