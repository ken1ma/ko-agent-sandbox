package fixture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

// The gate's `run` task: creates a temporary file, where the forked JVM's profile allows or not,
// and prints where; with `sleep`, stays up for the cancel and teardown rows.
public final class Main {
  private Main() {}

  public static void main(String[] args) throws IOException, InterruptedException {
    Path file = Files.createTempFile("fixture", ".tmp");
    System.out.println("fixture-main tmpfile=" + file);
    Files.delete(file);
    if (Arrays.asList(args).contains("sleep")) {
      Thread.sleep(600_000);
    }
  }
}
