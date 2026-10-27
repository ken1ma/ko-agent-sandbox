#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ProbeHelper.scala

// The evidence check of doc/plan-bpf-lsm-cgroup.md ("Phases", 4): each measurement section of the
// plan names the SHA-256 of the sources its probe was built from, and this check recomputes it, so
// that a section cannot stand as evidence for a program it did not measure. Run it from the
// repository root:
//
//     bpf/probe/CheckEvidence.scala
//
// On Windows, where no shebang runs, the same is `scala shebang bpf\probe\CheckEvidence.scala`.
//
// For every `### Phase N on PLATFORM` section holding `sources of SHA-256 \`HASH\``, the hash is
// recomputed over the files bpf/probe/phaseN/sources.txt lists, in that order, concatenated; the
// drivers record the same hash in their build output. A section without the phrase passes, reported,
// when its phase has no sources.txt: Phases 1 and 2 name their object's hash alone. Exit status 1 when
// a named hash differs, a phase's sources.txt is missing, or a section of a phase that has one names
// no hash.

import java.nio.file.Files

import ProbeHelper.*

@main def check(): Unit = CheckEvidence.run()

object CheckEvidence:

  /** A measurement section: its phase, its platform and the sources hash it names, if any. */
  case class Section(phase: String, platform: String, sourcesSha: Option[String])

  private val heading = raw"^### Phase (\d+) on (\S+)".r
  private val sourcesSha = raw"sources\s+of\s+SHA-256\s+`([0-9a-f]{64})`".r

  /** The measurement sections of the plan, each running to the next heading of its level or above; the
    * phrase and its hash may break across lines. */
  def sections(plan: String): Seq[Section] =
    val headed = plan.linesIterator.foldLeft(Vector.empty[(Option[(String, String)], StringBuilder)]):
      (blocks, line) =>
        line match
          case heading(phase, platform) => blocks :+ (Some((phase, platform)), StringBuilder())
          case _ if line.startsWith("## ") || line.startsWith("### ") => blocks :+ (None, StringBuilder())
          case _ =>
            blocks.lastOption.foreach((_, text) => text.append(line).append('\n'))
            blocks
    headed.collect:
      case (Some((phase, platform)), text) =>
        Section(phase, platform, sourcesSha.findFirstMatchIn(text.toString).map(_.group(1)))

  def run(): Unit =
    val repoDir = orExit(repositoryRoot("doc/plan-bpf-lsm-cgroup.md", "bpf/probe"))
    val probeDir = repoDir / "bpf" / "probe"
    val results = sections(Files.readString(repoDir / "doc" / "plan-bpf-lsm-cgroup.md")).map: section =>
      val name = s"Phase ${section.phase} on ${section.platform}"
      val sourcesList = probeDir / s"phase${section.phase}" / "sources.txt"
      section.sourcesSha match
        case None if Files.exists(sourcesList) =>
          println(s"FAIL $name names no sources hash, and $sourcesList lists its phase's sources")
          false
        case None =>
          println(s"INFO $name names no sources hash")
          true
        case Some(_) if !Files.exists(sourcesList) =>
          println(s"FAIL $name: $sourcesList is missing")
          false
        case Some(named) =>
          val sources = Files.readString(sourcesList).linesIterator.filter(_.nonEmpty).toSeq
          val actual = sha256(sources.map(source => Files.readAllBytes(sourcesList.getParent / source)))
          if actual == named then println(s"PASS $name: sources $named")
          else println(s"FAIL $name: the section names $named, the sources hash to $actual")
          actual == named
    sys.exit(if results.forall(identity) then 0 else 1)
