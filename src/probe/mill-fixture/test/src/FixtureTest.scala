package fixture

import java.nio.file.Files

class FixtureTest extends munit.FunSuite:
  test("greets"):
    assertEquals(Fixture.greeting("gate"), "hello, gate")

  // The test JVM is the daemon's fork under the daemon's profile, with the command's environment:
  // a temporary file must be creatable where that environment says.
  test("writes a temporary file"):
    Files.delete(Files.createTempFile("fixture", ".tmp"))
