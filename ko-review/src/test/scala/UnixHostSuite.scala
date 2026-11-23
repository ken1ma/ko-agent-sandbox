package koreview

/** A suite whose every test skips in a Windows JVM, giving `unixHostClue` as the reason. munit has no suite-level
  * assume, so a transform runs the assume before each test's body.
  *
  * A copy of the launcher's `UnixHostSuite`: this build does not see the launcher's test classes. */
trait UnixHostSuite extends munit.FunSuite:
  /** What the suite needs from a Unix host. */
  def unixHostClue: String

  /** Whether this JVM runs the suite's tests. munit runs `beforeEach` before the skip, so setup checks this. */
  val unixHost: Boolean = !scala.util.Properties.isWin

  override def munitTestTransforms: List[TestTransform] =
    super.munitTestTransforms :+ TestTransform(
      "needs a Unix host",
      test =>
        test.withBody: () =>
          assume(unixHost, unixHostClue)
          test.body()
      ,
    )
