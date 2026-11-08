package agentsandbox.launcher

class InspectionCaTest extends munit.FunSuite:

  test("the CA names the workspace"):
    val ca = InspectionCa.create("myproj").certificate
    assert(ca.getSubjectX500Principal.getName.contains("myproj"))

  test("the longest name a launch can ask for, a full slug and a run suffix, fits the common name's 64"):
    val slug = "a" * 32
    val ca = InspectionCa.create(s"$slug 1a2b3c4d").certificate
    assert(ca.getSubjectX500Principal.getName.contains(slug))
