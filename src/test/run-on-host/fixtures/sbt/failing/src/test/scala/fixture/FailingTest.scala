package fixture

class FailingTest extends munit.FunSuite:
  test("fails, so that the command's exit code is a failure's"):
    fail("the fixture's failing test")
