package fixture;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

// The acceptance test's `run` task creates a temporary file, which the forked JVM's profile allows or refuses, and
// prints the file's path. With the argument `sleep`, the task stays up for the cancel and teardown rows.
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
