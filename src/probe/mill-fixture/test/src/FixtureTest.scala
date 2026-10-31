package fixture

import java.nio.file.Files

class FixtureTest extends munit.FunSuite:
  test("greets"):
    assertEquals(Fixture.greeting("acceptance"), "hello, acceptance")

  // The test JVM is a fork of the daemon and runs under the daemon's profile with the command's environment. The test
  // must be able to create a temporary file where that environment says.
  test("writes a temporary file"):
    Files.delete(Files.createTempFile("fixture", ".tmp"))
