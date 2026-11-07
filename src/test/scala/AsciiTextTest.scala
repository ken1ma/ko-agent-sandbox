// The launcher's own text is ASCII (design.md, "The launcher's text is ASCII"). The check reads the
// compiled classes rather than the sources. The classes hold every literal and no comment, and the
// literals include the scripts that the launcher embeds and the egress proxy's text.

package agentsandbox.launcher

import scala.jdk.CollectionConverters.*

import java.lang.classfile.ClassFile
import java.lang.classfile.constantpool.StringEntry

class AsciiTextTest extends munit.FunSuite:

  /** Each class file compiled from the launcher's sources and the proxy's, by name (CompiledOutput). */
  private def compiledClasses(): Vector[(String, Array[Byte])] =
    CompiledOutput.allEntries.collect { case (name, bytes) if name.endsWith(".class") => name -> bytes() }

  /** The non-ASCII sequences that a class matches or writes into a script but never prints as text.
    * The check removes them from each constant of that class, the longer sequences first. */
  private val Recognized: Map[String, Vector[String]] = Map(
    // PowerShell takes these characters for quotes, so the launcher quotes and escapes a path that holds one.
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
    CompiledOutput.RepresentativeEntries.foreach: entry =>
      assert(classes.exists(_._1 == entry), s"$entry is not among ${classes.map(_._1)}")
    val offending =
      for
        (name, bytes) <- classes
        constant <- ClassFile.of().parse(bytes).constantPool.iterator.asScala
        text <- Some(constant).collect { case string: StringEntry => string.stringValue }
        rest = Recognized.getOrElse(name, Vector.empty).foldLeft(text)(_.replace(_, ""))
        if rest.exists(_ >= 0x80)
      yield s"$name: ${escaped(text)}"
    assert(offending.isEmpty, offending.distinct.mkString("\n"))
