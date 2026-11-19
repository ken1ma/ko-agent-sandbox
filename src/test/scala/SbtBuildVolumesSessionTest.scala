// Tests, against a real session, which sbt builds a launch gives a project/target of their own: an eligible build
// gets a volume that the host does not see, and a build under a read-only file rule gets none and no directory.
// SbtBuildVolumesTest tests the walk and the plan; this suite asks what the session and the host see.
//
// The suite runs only under testWithPodman, like the other container-launching suites (WithPodman has the
// condition):
//
//     sbt "testWithPodman *SbtBuildVolumesSessionTest"

package agentsandbox.launcher

import java.nio.file.Files

import WithPodman.*

class SbtBuildVolumesSessionTest extends munit.FunSuite:

  override val munitTimeout = scala.concurrent.duration.Duration(15, "min")

  test("an eligible build's project/target is the session's own, and a build under a read-only rule gets none"):
    requireTestWithPodman()
    val workspaceRoot = scratchWorkspace()
    try
      Files.writeString(workspaceRoot.resolve("build.sbt"), "")
      Files.writeString(Files.createDirectories(workspaceRoot.resolve("vendor/lib")).resolve("build.sbt"), "")
      Files.writeString(
        Files.createDirectories(workspaceRoot.resolve(".ko-agent-sandbox/file")).resolve("rule"),
        "read-only vendor\n",
      )
      val options = Vector(workspaceOption("live"), "--egress=deny-unless-allowed")
      val session = launchWith(workspaceRoot, workspaceRoot.resolve("session.log"), options)
      try
        val root = mountPath(session)
        val mounts = exec(session, "cat", "/proc/self/mountinfo").text.linesIterator
          .map(line => unescapeMountinfo(line.split(" ")(4))).toSet
        assert(
          mounts.contains(s"$root/project/target"),
          s"no volume at $root/project/target:\n${mounts.mkString("\n")}",
        )
        assert(!mounts.contains(s"$root/vendor/lib/project/target"), "the build under the read-only rule got a volume")
        assert(exec(session, "touch", s"$root/project/target/session-only").ok, "the volume is not writable")
        assert(Files.isDirectory(workspaceRoot.resolve("project/target")), "the launch did not create project/target")
        assert(!Files.exists(workspaceRoot.resolve("project/target/session-only")), "the host sees the volume's file")
        assert(!Files.exists(workspaceRoot.resolve("vendor/lib/project")), "the launch created a read-only directory")
        assert(session.output.contains("a read-only file rule covers"), session.output)
      finally stop(session)
    finally discard(workspaceRoot)
