// The compiled output that the test JVM runs: the launcher's classes and the egress proxy's, which the egressProxy
// subproject compiles apart (build.sbt). A check that reads one code source alone covers the launcher and silently
// drops the proxy, so the checks that read compiled bytes take every code source from here.

package agentsandbox.launcher

import scala.jdk.CollectionConverters.*
import scala.util.Using

import java.nio.file.{Files, Path, Paths}
import java.util.jar.JarFile

object CompiledOutput:

  /** One class of each project, so that every project's output is found. */
  private val Representatives: Vector[Class[?]] =
    Vector(AgentSandboxLauncher.getClass, agentsandbox.egress.AgentEgressProxy.getClass)

  /** Each project's code source, a directory or a jar, as sbt exposes it. */
  def codeSources: Vector[Path] =
    Representatives.map(cls => Paths.get(cls.getProtectionDomain.getCodeSource.getLocation.toURI)).distinct

  /** The regular entries of one code source, by their `/`-separated name, with their bytes read lazily. */
  def entries(codeSource: Path): Vector[(String, () => Array[Byte])] =
    if Files.isDirectory(codeSource) then
      Using.resource(Files.walk(codeSource)): files =>
        files.iterator.asScala.filter(Files.isRegularFile(_)).map: file =>
          codeSource.relativize(file).iterator.asScala.mkString("/") -> (() => Files.readAllBytes(file))
        .toVector
    else
      Using.resource(JarFile(codeSource.toFile)): jar =>
        jar.entries.asScala.filterNot(_.isDirectory).map: entry =>
          val bytes = Using.resource(jar.getInputStream(entry))(_.readAllBytes())
          entry.getName -> (() => bytes)
        .toVector

  /** Every entry of every code source. */
  def allEntries: Vector[(String, () => Array[Byte])] = codeSources.flatMap(entries)

  /** An entry of each project, which a check asserts it saw, so that a project's output cannot drop out of the check
    * unnoticed. */
  val RepresentativeEntries: Vector[String] =
    Vector("agentsandbox/launcher/AgentSandboxLauncher$.class", "agentsandbox/egress/AgentEgressProxy$.class")
