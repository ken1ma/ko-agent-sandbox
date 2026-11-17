#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../test/scala/HostDriver.scala
//> using file ../test/scala/RunOnHostIdle.scala
//> using file ../test/scala/RunOnHostChecks.scala

/*
  Shows what the sbt that cs installed runs: the script's exec target, the distribution beside that target, and the
  interpreters the chain needs. SeatbeltProfile grants the distribution's home directory, and this probe confirms that
  path.

  Run the probe on the macOS HOST after upgrading sbt or reinstalling sbt with cs: the distribution path contains the
  sbt version that Coursier fetched, so the path moves.

      src/probe/SbtExecChain.scala [OUT]      # OUT defaults to /tmp/sbt-exec-chain.txt

  The probe writes to a file rather than the terminal. A program that Coursier installs carries an appended jar, so
  printing the program dumps binary and fills the scrollback.
*/

import agentsandbox.launcher.HostDriver
import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*

import java.nio.file.{Files, Path, StandardOpenOption}
import java.util.regex.Pattern

import scala.jdk.CollectionConverters.*

@main def execChain(args: String*): Unit = SbtExecChain.run(args)

object SbtExecChain:
  private val env: String => Option[String] = sys.env.get

  def run(args: Seq[String]): Unit =
    orExit(Either.cond(sys.props("os.name") == "Mac OS X", (), "Run this on macOS."))
    val home = orExit(env("HOME").filter(_.nonEmpty).map(Path.of(_)).toRight("HOME is not set"))
    val out = Path.of(args.headOption.getOrElse("/tmp/sbt-exec-chain.txt"))
    Files.writeString(out, "")
    def write(lines: Iterable[String]): Unit =
      Files.write(out, lines.asJava, StandardOpenOption.APPEND)
    def note(title: String): Unit = write(Seq("", s"=== $title ==="))

    val script =
      orExit(onPath("sbt").map(_.toRealPath()).toRight("no sbt on PATH; install it with `cs install sbt`"))
    // Text lines only, so that the appended jar reaches neither the file nor the path searches.
    val scriptLines = leadingTextLines(script)
    val scriptText = scriptLines.mkString("\n")

    note(s"script: $script")
    write(scriptLines.take(80).filter(_.nonEmpty))

    note("absolute paths the script names")
    write("/[A-Za-z0-9_./ +%-]{8,}".r.findAllIn(scriptText).toVector.distinct.sorted)

    val distributionSbt =
      userCoursierDirectory(env, home, CoursierDirectory.Archive) match
        case Left(reason) =>
          note(reason)
          None
        case Right(archive) =>
          s"${Pattern.quote(archive.toString)}/[^\"']*".r.findFirstIn(scriptText).map(Path.of(_))
    note(s"distribution sbt: ${distributionSbt.fold("NOT FOUND")(_.toString)}")
    distributionSbt.filter(Files.isRegularFile(_)).foreach: inner =>
      write(HostDriver.run(Seq("/bin/ls", "-l", inner.toString)).text.linesIterator.toSeq)
      note("distribution sbt, text")
      write(leadingTextLines(inner).take(120).filter(_.nonEmpty))
      note("what the distribution ships")
      write(listedNames(inner.getParent))
      write(listedNames(inner.getParent.getParent))

    note("interpreters the chain needs")
    write(Seq("/usr/bin/env", "/bin/sh", "/bin/bash", "/usr/bin/dirname", "/usr/bin/uname", "/usr/bin/sed")
      .filter(candidate => Files.isExecutable(Path.of(candidate))).map(candidate => s"$candidate present"))

    println(s"written to $out")
    println(s"review it with:  less $out")
