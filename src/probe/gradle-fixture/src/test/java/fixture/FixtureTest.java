package fixture;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;

class FixtureTest {
  @Test
  void answers() {
    assertEquals(42, Fixture.answer());
  }

  // The test JVM is the daemon's fork under the command's profile, with the command's
  // environment: a temporary file must be creatable where that environment says.
  @Test
  void writesATemporaryFile() throws IOException {
    Files.delete(Files.createTempFile("fixture", ".tmp"));
  }
}
