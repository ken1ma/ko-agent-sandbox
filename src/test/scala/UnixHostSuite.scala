package agentsandbox.launcher

/** A suite whose every test skips in a Windows JVM, giving `unixHostClue` as the reason. munit has no suite-level
  * assume, so a transform runs the assume before each test's body. */
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

/** Fixtures spelled as macOS or Linux paths, such as `/home/me`. A Windows JVM reads them as relative, prints them with
  * `\` and refuses a `:` in one, so a test of macOS or Linux behavior over them runs on those hosts alone. */
object PosixPaths:
  /** Whether this JVM reads the fixtures as written. */
  val readable: Boolean = !scala.util.Properties.isWin

  /** Skips the test where this JVM does not read the fixtures as written. */
  def assume()(using munit.Location): Unit =
    munit.Assertions.assume(readable, "a Windows JVM reads the test's POSIX paths as Windows paths")
