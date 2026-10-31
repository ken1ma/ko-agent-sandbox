package fixture

import java.nio.file.Files

// The acceptance test's `run` target creates a temporary file, which the forked JVM's profile allows or refuses, and
// prints the file's path. With the argument `sleep`, the target stays up for the cancel and foreign-daemon rows.
object Main:
  def main(args: Array[String]): Unit =
    val file = Files.createTempFile("fixture", ".tmp")
    println(s"fixture-main tmpfile=$file")
    Files.delete(file)
    if args.contains("sleep") then Thread.sleep(600_000)
