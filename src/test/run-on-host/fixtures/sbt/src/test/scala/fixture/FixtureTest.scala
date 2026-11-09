package fixture

import java.nio.file.Files

class FixtureTest extends munit.FunSuite:
  test("greets"):
    assertEquals(Fixture.greeting("run-on-host"), "hello, run-on-host")

  // The test runs under the command's profile with the command's environment, and must be able to create a temporary
  // file where that environment says.
  test("writes a temporary file"):
    Files.delete(Files.createTempFile("fixture", ".tmp"))
