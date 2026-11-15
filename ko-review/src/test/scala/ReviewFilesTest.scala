package koreview

import io.circe.{Decoder, Encoder, Json}
import io.circe.syntax.*
import java.nio.file.{Files, Path}
import scala.compiletime.constValueTuple
import scala.deriving.Mirror
import scala.jdk.CollectionConverters.*
import ReviewFiles.*

/** The review files' format: samples of every format version stay readable, and the current version's samples set
  * every field, so that a change to the classes fails here until it comes with a new format version and its samples
  * (ReviewFiles.scala, rule 5). */
class ReviewFilesTest extends munit.FunSuite:

  private val samples = Path.of("src/test/resources/review-files")

  private inline def labels[T](using mirror: Mirror.ProductOf[T]): Set[String] =
    constValueTuple[mirror.MirroredElemLabels].toList.map(_.toString).toSet

  /** Each file's class, by the name before the first `-` or `.`. */
  private def check(name: String, json: Json): Either[String, Json] =
    def roundTrip[T: Decoder: Encoder]: Either[String, Json] =
      json.as[T].left.map(_.getMessage).map(_.asJson.deepDropNullValues)
    name.takeWhile(c => c != '-' && c != '.') match
      case "worktree" => roundTrip[WorktreeFile]
      case "start" => roundTrip[StartFile]
      case "request" => roundTrip[RequestFile]
      case "thread" => roundTrip[ThreadFile]
      case "outcome" => roundTrip[OutcomeFile]
      case "escalation" => roundTrip[EscalationFile]
      case "manifest" => roundTrip[ManifestFile]
      case other => Left(s"no class for $other")

  private def files(version: Path): Vector[Path] =
    Files.list(version).iterator().asScala.toVector.sortBy(_.getFileName.toString)

  test("every sample of every format version decodes, and a round trip keeps each of its fields"):
    val versions = Files.list(samples).iterator().asScala.toVector
    assert(versions.exists(_.getFileName.toString == FormatVersion), s"no samples for $FormatVersion")
    for version <- versions; file <- files(version) do
      val json = io.circe.parser.parse(Files.readString(file)).fold(throw _, identity)
      val roundTrip = check(file.getFileName.toString, json)
      if version.getFileName.toString == FormatVersion then
        assertEquals(roundTrip, Right(json.deepDropNullValues), file)
      else assert(roundTrip.isRight, s"$file: $roundTrip")

  test("the current samples set every field of the format's classes"):
    val current = files(samples.resolve(FormatVersion))
      .map(file => file.getFileName.toString -> io.circe.parser.parse(Files.readString(file)).fold(throw _, identity))
    def keysOf(prefix: String, path: String*): Set[String] =
      current.filter(_._1.startsWith(prefix)).flatMap: (_, json) =>
        path.foldLeft(Vector(json))((found, key) => found.flatMap(value =>
          value.asObject.flatMap(_(key)).toVector.flatMap(child => child.asArray.getOrElse(Vector(child)))))
          .flatMap(_.asObject.toVector.flatMap(_.keys))
      .toSet
    val expected = Seq(
      "WorktreeFile" -> (labels[WorktreeFile], keysOf("worktree")),
      "StartFile" -> (labels[StartFile], keysOf("start")),
      "Base" -> (labels[Base], keysOf("start", "base")),
      "RequestFile" -> (labels[RequestFile], keysOf("request")),
      "From" -> (labels[From], keysOf("request", "from")),
      "Coordinator" -> (labels[Coordinator], keysOf("request", "coordinator")),
      "ThreadFile" -> (labels[ThreadFile], keysOf("thread")),
      "OutcomeFile" -> (labels[OutcomeFile], keysOf("outcome")),
      "ReviewResult" -> (labels[ReviewResult], keysOf("outcome", "result")),
      "Finding" -> (labels[Finding], keysOf("outcome", "result", "findings")),
      "Suggestion" -> (labels[Suggestion], keysOf("outcome", "result", "suggestions")),
      "UserDecision" -> (labels[UserDecision], keysOf("outcome", "result", "userDecision")),
      "EscalationFile" -> (labels[EscalationFile], keysOf("escalation")),
      "ManifestFile" -> (labels[ManifestFile], keysOf("manifest")),
    )
    for (name, (fields, sampled)) <- expected do
      assertEquals(fields, sampled, s"$name: bump ReviewFiles.FormatVersion and add samples under the new version")

  test("a reader ignores fields it does not know, and a missing field takes its declared default"):
    val start = io.circe.parser.decode[StartFile]("""{"formatVersion": "0.2.0", "writtenAt": "2026-11-15T04:00:24.990Z",
      "addedLater": {"any": "shape"}}""")
    assertEquals(start, Right(StartFile("0.2.0", "2026-11-15T04:00:24.990Z")))
    assertEquals(start.toOption.get.maxAnsweredTurns, 12)
    assert(io.circe.parser.decode[RequestFile]("""{"formatVersion": "0.2.0", "writtenAt": "x"}""").isLeft,
      "a field without a default is required")

  test("a newer minor version stops a helper from continuing, and a newer patch does not"):
    assertEquals(newerFormat(FormatVersion), false)
    assertEquals(newerFormat("0.2.9"), false)
    assertEquals(newerFormat("0.1.0"), false)
    assertEquals(newerFormat("0.3.0"), true)
    assertEquals(newerFormat("1.0.0"), true)
    assertEquals(newerFormat("garbled"), true)

  test("a record is written once"):
    val directory = Files.createTempDirectory("ko-review-files-")
    try
      val path = directory.resolve("thread.json")
      write(path, ThreadFile(FormatVersion, now(), "t"))
      intercept[java.nio.file.FileAlreadyExistsException](write(path, ThreadFile(FormatVersion, now(), "other")))
      assertEquals(read[ThreadFile](path).map(_.threadId), Right("t"))
      assertEquals(Files.list(directory).count(), 1L, "no temporary file stays")
    finally HelperFixture.deleteTree(directory)
