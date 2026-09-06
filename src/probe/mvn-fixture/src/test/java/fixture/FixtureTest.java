package fixture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class FixtureTest {
  @Test
  void answers() {
    assertEquals(42, Fixture.answer());
  }
}
