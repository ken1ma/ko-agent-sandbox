package fixture

class FixtureTest extends munit.FunSuite:
  test("greets"):
    assertEquals(Fixture.greeting("gate"), "hello, gate")
