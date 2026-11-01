// Tests the podman behavior that ImageBuilds.sandboxStageTagCommands relies on, on a fixture shaped like the
// sandbox Containerfile: a `tools` stage, two stages built on it, and a final stage that copies from both through
// bind mounts.
//
// - After a `--jobs` build, a `--target` build per stage tags the stage image that the build committed.
// - After a `--no-cache` rebuild, the same `--target` builds tag the rebuild's stage images.
// - The launcher's removal of the superseded ids, then of the current ones, leaves no image of the fixture.
//
// Each stage writes a fresh timestamp, so equal contents show that two images come from one build. Every image of
// the fixture carries the label RunLabel, and the suite removes any that an interrupted run left.
//
// The suite runs only under testWithPodman, like the other container-launching suites (WithPodman has the
// condition):
//
//     sbt "testWithPodman *StageCacheTagTest"

package agentsandbox.launcher

import java.nio.file.Files

import FileHelper.deleteRecursively
import HostCommands.*
import ImageBuilds.NoRegistryLookup
import LauncherImages.*
import WithPodman.*

class StageCacheTagTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(10, "min")

  private val Stages = Vector("one", "two")
  private val RunLabel = "ko-agent-sandbox.stage-cache-test"
  private val FinalImage = "ko-agent-stage-cache-test:latest"
  private def stageImage(stage: String): String = s"ko-agent-stage-cache-test-$stage:cache"

  private val Fixture =
    Vector(
      "ARG BASE",
      "FROM ${BASE} AS tools",
      "ARG RUN_ID",
      s"LABEL $RunLabel=$${RUN_ID}",
      "RUN echo tools > /tools",
    ).mkString("", "\n", "\n")
      + Stages.map(stage => s"FROM tools AS $stage\nRUN mkdir /out && date +%s%N > /out/$stage\n").mkString
      + "FROM tools\n"
      + "RUN "
      + Stages.map(stage => s"--mount=type=bind,from=$stage,source=/out,target=/mnt/$stage ").mkString
      + "mkdir /stage && " + Stages.map(stage => s"cp -a /mnt/$stage/* /stage/").mkString(" && ") + "\n"

  private def labelledImages(): Vector[String] =
    val listed = run(podman, "images", "-a", "-q", "--no-trunc", "--filter", s"label=$RunLabel")
    assert(listed.ok, s"podman images failed: ${listed.err}")
    listed.text.linesIterator.map(_.trim).filter(_.nonEmpty).toVector.distinct

  private def removeLabelledImages(): Unit =
    labelledImages().foreach(id => run(podman, "image", "rm", "--force", "--ignore", id))

  private def imageId(image: String): String =
    val inspected = run(podman, "image", "inspect", "--format", "{{.Id}}", image)
    assert(inspected.ok, s"could not inspect $image: ${inspected.err}")
    inspected.text.trim

  private def contents(image: String, path: String): String =
    val shown = run(podman, "run", "--rm", "--pull=never", "--network=none", "--entrypoint", "cat", image, path)
    assert(shown.ok, s"could not read $path in $image: ${shown.err}")
    shown.text.trim

  test("a --target build tags the stage image that the preceding --jobs build committed, with or without cache"):
    requireTestWithPodman()
    removeLabelledImages()
    val context = Files.createTempDirectory("stage-cache-test")
    try
      Files.writeString(context.resolve("Containerfile"), Fixture)
      val buildArgs = Vector(
        "--build-arg", s"BASE=${coursierImage(ImgTagVersion)}",
        "--build-arg", s"RUN_ID=${java.util.UUID.randomUUID}",
      )
      def build(options: String*): Unit =
        val built = run((Vector(podman, "build", NoRegistryLookup) ++ options ++ buildArgs :+ context.toString)*)
        assert(built.ok, s"podman build ${options.mkString(" ")} failed:\n${built.err}")
      // The order of buildImageTags: the final image, then its stages.
      val tags = FinalImage +: Stages.map(stageImage)
      def buildRound(cache: String*): Vector[String] =
        build((cache ++ Vector("--jobs", "2", "--label", s"$BundleLabel=fixture", "-t", FinalImage))*)
        Stages.foreach(stage => build("--target", stage, "-t", stageImage(stage)))
        Stages.foreach: stage =>
          assertEquals(contents(stageImage(stage), s"/out/$stage"), contents(FinalImage, s"/stage/$stage"), stage)
        tags.map(imageId)

      val first = buildRound()
      val firstStage = contents(stageImage(Stages.head), s"/out/${Stages.head}")
      val second = buildRound("--no-cache")
      assertNotEquals(contents(stageImage(Stages.head), s"/out/${Stages.head}"), firstStage)

      // A stage image that no tag reached would outlive both removals.
      val removals = supersededImageRemoveCommands(podman, first.reverse, second)
        ++ supersededImageRemoveCommands(podman, second.reverse, Vector.empty)
      removals.foreach: command =>
        val removed = run(command*)
        assert(removed.ok, s"${command.mkString(" ")} failed: ${removed.err}")
      assertEquals(labelledImages(), Vector.empty, "an image of the fixture outlived the removal of every tag")
    finally
      removeLabelledImages()
      deleteRecursively(context)
