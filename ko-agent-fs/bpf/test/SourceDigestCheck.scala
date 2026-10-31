#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../../../src/main/scala/SourceDigest.scala

// Checks the source digests that ko-agent-fs/bpf/doc/evidence.md names ("Suites"). Each measurement
// section names the digest of the sources its suite was built from. This check recomputes it, so a
// section cannot stand as evidence for code it did not measure. The digest covers the sources' code,
// without comments (src/main/scala/SourceDigest.scala), and not the evidence. Run it from the
// repository root:
//
//     ko-agent-fs/bpf/test/SourceDigestCheck.scala
//
// On Windows, where no shebang runs, use `scala shebang ko-agent-fs\bpf\test\SourceDigestCheck.scala`.
//
// - For every `### SUITE on PLATFORM` section that contains `sources of code digest \`DIGEST\``, the
//   digest is recomputed over the files that podman/SUITE/sources.txt lists, in that order. SUITE is
//   the suite's name in lower case, with dashes for spaces. The drivers record the same digest in their
//   build output.
// - A section without the phrase passes, and is reported, when its suite has no directory: the retired
//   one-hook and every-hook suites name only their object's hash.
// - Exit status 1 when a named digest differs, when a suite's sources.txt is missing, or when a section
//   of a suite that has a directory names no digest. Exit status 2 when not run from the repository
//   root.

import java.nio.file.{Files, Path}

import agentsandbox.launcher.SourceDigest

@main def check(): Unit = SourceDigestCheck.run()

object SourceDigestCheck:

  val Evidence = "ko-agent-fs/bpf/doc/evidence.md"
  val Suites = "ko-agent-fs/bpf/test/podman"

  /** A measurement section: its suite, its platform and the sources digest it names, if any. */
  case class Section(suite: String, platform: String, sourcesDigest: Option[String])

  private val heading = raw"^### (.+) on (macOS|WSL)$$".r
  private val namedDigest = raw"sources\s+of\s+code\s+digest\s+`([0-9a-f]{64})`".r

  /** The measurement sections of the evidence document. Each runs to the next heading of its level or
    * higher. The phrase and its digest may be split across lines. */
  def sections(evidence: String): Seq[Section] =
    val headed = evidence.linesIterator.foldLeft(Vector.empty[(Option[(String, String)], StringBuilder)]):
      (blocks, line) =>
        line match
          case heading(suite, platform) => blocks :+ (Some((suite, platform)), StringBuilder())
          case _ if line.startsWith("## ") || line.startsWith("### ") => blocks :+ (None, StringBuilder())
          case _ =>
            blocks.lastOption.foreach((_, text) => text.append(line).append('\n'))
            blocks
    headed.collect:
      case (Some((suite, platform)), text) =>
        Section(suite, platform, namedDigest.findFirstMatchIn(text.toString).map(_.group(1)))

  def run(): Unit =
    val repoDir = Path.of("").toAbsolutePath
    if !Seq(Evidence, Suites).forall(path => Files.exists(repoDir.resolve(path))) then
      System.err.println(s"$repoDir is not the repository root; run this from it")
      sys.exit(2)
    val results = sections(Files.readString(repoDir.resolve(Evidence))).map: section =>
      val name = s"${section.suite} on ${section.platform}"
      val suiteDir = repoDir.resolve(Suites).resolve(section.suite.toLowerCase.replace(' ', '-'))
      val sourcesList = suiteDir.resolve("sources.txt")
      section.sourcesDigest match
        case None if Files.isDirectory(suiteDir) =>
          println(s"FAIL $name names no sources digest, and $suiteDir is its suite")
          false
        case None =>
          println(s"INFO $name names no sources digest")
          true
        case Some(_) if !Files.exists(sourcesList) =>
          println(s"FAIL $name: $sourcesList is missing")
          false
        case Some(named) =>
          val actual = SourceDigest.ofList(sourcesList)
          if actual == named then println(s"PASS $name: sources $named")
          else println(s"FAIL $name: the section names $named, the sources digest to $actual")
          actual == named
    sys.exit(if results.forall(identity) then 0 else 1)
