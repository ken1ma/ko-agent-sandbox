package agentsandbox.launcher

object BundledBuildContext extends munit.Assertions:

  /** A bundled build-context entry, as the resourceGenerators task in build.sbt wrote it into the jar. */
  def resource(name: String): String =
    val stream = getClass.getResourceAsStream(s"/sandbox-build/$name")
    assert(stream != null, name)
    try String(stream.readAllBytes(), "UTF-8")
    finally stream.close()
