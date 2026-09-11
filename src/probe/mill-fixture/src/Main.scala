package fixture

import java.nio.file.Files

// The gate's `run` target: creates a temporary file, where the forked JVM's profile allows or not,
// and prints where; with `sleep`, stays up for the cancel and foreign-daemon rows.
object Main:
  def main(args: Array[String]): Unit =
    val file = Files.createTempFile("fixture", ".tmp")
    println(s"fixture-main tmpfile=$file")
    Files.delete(file)
    if args.contains("sleep") then Thread.sleep(600_000)
