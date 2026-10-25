// The seccomp profile of a --nesting=none session: what it takes from podman's default, what it
// adds, and how the build reads the default out of the podman host.

package agentsandbox.launcher

import java.nio.file.{Files, Paths}

import JsonText.Json
import JsonText.Json.*
import SeccompProfile.*

class SeccompProfileTest extends munit.FunSuite:

  private def parsed(text: String): Json = JsonText.parse(text).fold(reason => fail(reason), identity)

  /** The default's shape: an unconditional refusal, the unconditional allow list that names every
    * refused syscall, a conditional rule, capability-gated rules, and the format's older `name`. */
  private val Default = parsed(
    """{
      |  "defaultAction": "SCMP_ACT_ERRNO",
      |  "defaultErrnoRet": 38,
      |  "defaultErrno": "ENOSYS",
      |  "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]}],
      |  "syscalls": [
      |    {"names": ["kexec_load", "vm86"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [], "comment": "",
      |     "includes": {}, "excludes": {}},
      |    {"names": ["accept", "clone", "clone3", "fsconfig", "fsmount", "fsopen", "fspick", "mount",
      |               "mount_setattr", "move_mount", "open_tree", "pivot_root", "read", "setns", "umount",
      |               "umount2", "unshare", "write"],
      |     "action": "SCMP_ACT_ALLOW", "args": [], "comment": "", "includes": {}, "excludes": {}},
      |    {"names": ["personality"], "action": "SCMP_ACT_ALLOW",
      |     "args": [{"index": 0, "value": 0, "valueTwo": 0, "op": "SCMP_CMP_EQ"}], "comment": "", "includes": {},
      |     "excludes": {}},
      |    {"names": ["setns"], "action": "SCMP_ACT_ALLOW", "args": [], "comment": "",
      |     "includes": {"caps": ["CAP_SYS_ADMIN"]}, "excludes": {}},
      |    {"names": ["setns"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [], "comment": "", "includes": {},
      |     "excludes": {"caps": ["CAP_SYS_ADMIN"]}},
      |    {"name": "mount", "action": "SCMP_ACT_ALLOW", "args": [], "comment": "", "includes": {}, "excludes": {}},
      |    {"names": ["chroot"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [], "comment": "", "includes": {},
      |     "excludes": {"caps": ["CAP_SYS_CHROOT"]}}
      |  ]
      |}""".stripMargin,
  )

  private def rules(profile: Json): Vector[Json] =
    profile.field("syscalls") match
      case Some(Arr(items)) => items
      case other            => fail(s"no syscalls array: $other")

  private def names(rule: Json): Vector[String] =
    rule.field("names") match
      case Some(Arr(items)) => items.collect { case Str(name) => name }
      case _                => rule.field("name").collect { case Str(name) => name }.toVector

  test("the derived profile is the default with the refused names taken out and the launcher's rules appended"):
    val derived = SeccompProfile.derived(Default).fold(reason => fail(reason), identity)
    val expected = parsed(
      """{
        |  "defaultAction": "SCMP_ACT_ERRNO",
        |  "defaultErrnoRet": 38,
        |  "defaultErrno": "ENOSYS",
        |  "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86", "SCMP_ARCH_X32"]}],
        |  "syscalls": [
        |    {"names": ["kexec_load", "vm86"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [], "comment": "",
        |     "includes": {}, "excludes": {}},
        |    {"names": ["accept", "read", "write"],
        |     "action": "SCMP_ACT_ALLOW", "args": [], "comment": "", "includes": {}, "excludes": {}},
        |    {"names": ["personality"], "action": "SCMP_ACT_ALLOW",
        |     "args": [{"index": 0, "value": 0, "valueTwo": 0, "op": "SCMP_CMP_EQ"}], "comment": "", "includes": {},
        |     "excludes": {}},
        |    {"names": ["chroot"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1, "args": [], "comment": "", "includes": {},
        |     "excludes": {"caps": ["CAP_SYS_CHROOT"]}}
        |  ]
        |}""".stripMargin,
    )
    val expectedRules = rules(expected) ++ AddedRules
    assertEquals(derived, Obj(expected.asInstanceOf[Obj].fields.map {
      case ("syscalls", _) => "syscalls" -> Arr(expectedRules)
      case other           => other
    }))
    // Rendered and read back, it is the same profile.
    assertEquals(JsonText.parse(JsonText.render(derived)), Right(derived))

  test("every refused syscall is decided by the launcher's rules alone, and no other syscall by them"):
    val derived = SeccompProfile.derived(Default).fold(reason => fail(reason), identity)
    val (added, kept) = rules(derived).partition(AddedRules.contains)
    assertEquals(added, AddedRules)
    assertEquals(kept.flatMap(names).filter(RefusedNames.contains), Vector.empty)
    assertEquals(AddedRules.flatMap(names).filterNot(RefusedNames.contains), Vector.empty)
    assertEquals(AddedRules.flatMap(names).toSet, RefusedNames.toSet)

  test("the added rules refuse CLONE_NEWUSER with EPERM, clone3 with ENOSYS, and joining or mounting with EPERM"):
    def rule(index: Int, field: String): Option[Json] = AddedRules(index).field(field)
    val mask = Num(0x10000000L.toString)
    def flagTest(expected: Json): Json =
      Arr(Vector(Obj(Vector(
        "index" -> Num("0"), "value" -> mask, "valueTwo" -> expected, "op" -> Str("SCMP_CMP_MASKED_EQ"),
      ))))
    assertEquals(names(AddedRules(0)), Vector("clone", "unshare"))
    assertEquals(rule(0, "action"), Some(Str("SCMP_ACT_ALLOW")))
    assertEquals(rule(0, "args"), Some(flagTest(Num("0"))))
    assertEquals(names(AddedRules(1)), Vector("clone", "unshare"))
    assertEquals((rule(1, "action"), rule(1, "errnoRet")), (Some(Str("SCMP_ACT_ERRNO")), Some(Num("1"))))
    assertEquals(rule(1, "args"), Some(flagTest(mask)))
    assertEquals(names(AddedRules(2)), Vector("clone3"))
    assertEquals((rule(2, "action"), rule(2, "errnoRet")), (Some(Str("SCMP_ACT_ERRNO")), Some(Num("38"))))
    assertEquals(names(AddedRules(3)), "setns" +: MountSyscalls)
    assertEquals((rule(3, "action"), rule(3, "errnoRet")), (Some(Str("SCMP_ACT_ERRNO")), Some(Num("1"))))
    assertEquals(rule(3, "args"), Some(Arr(Vector.empty)))

  test("a default without a syscalls array, or not an object, is refused"):
    assertEquals(SeccompProfile.derived(parsed("""{"defaultAction": "SCMP_ACT_ERRNO"}""")).isLeft, true)
    assertEquals(SeccompProfile.derived(parsed("[]")).isLeft, true)

  test("a default whose unnamed syscalls are permitted is refused, since the runtime skips a name libseccomp lacks"):
    def withDefault(action: Option[String]): Json =
      Obj(Default.asInstanceOf[Obj].fields.flatMap {
        case ("defaultAction", _) => action.map("defaultAction" -> Str(_))
        case other                => Some(other)
      })
    Vector("SCMP_ACT_ALLOW", "SCMP_ACT_LOG", "SCMP_ACT_NOTIFY", "SCMP_ACT_TRACE").foreach: action =>
      val refusal = SeccompProfile.derived(withDefault(Some(action)))
      assert(refusal.left.exists(_.startsWith(s"its defaultAction is $action, which permits")), s"$action: $refusal")
    assert(SeccompProfile.derived(withDefault(None)).left.exists(_.contains("absent")))
    RefusingDefaultActions.foreach: action =>
      assert(SeccompProfile.derived(withDefault(Some(action))).isRight, action)

  test("the default is read where podman reports it, else where podman looks, each directory bound read-only"):
    assertEquals(candidatePaths("/usr/share/containers/seccomp.json\n"), Vector("/usr/share/containers/seccomp.json"))
    assertEquals(candidatePaths("/etc/containers/mine.json"), Vector("/etc/containers/mine.json"))
    Vector("", "unconfined", "<no value>").foreach: reported =>
      assertEquals(candidatePaths(reported), DefaultProfilePaths, reported)
    val command = readDefaultCommand("podman", "ko-agent-sandbox:latest", DefaultProfilePaths)
    val (before, afterImage) = command.span(_ != "ko-agent-sandbox:latest")
    assertEquals(
      before,
      Vector(
        "podman", "run", "--rm", "--pull=never", "--network=none", "--security-opt=label=disable", "--entrypoint=",
        "--volume=/etc/containers:/mnt/seccomp/0:ro", "--volume=/usr/share/containers:/mnt/seccomp/1:ro",
      ),
    )
    assertEquals(afterImage.takeRight(2), Vector("/mnt/seccomp/0/seccomp.json", "/mnt/seccomp/1/seccomp.json"))
    assert(command.forall(word => !word.contains('"') && !word.contains('\n')), "a word a Windows launcher cannot pass")

  test("the read's answer is the path on the first line and the profile after it"):
    val path = "/usr/share/containers/seccomp.json"
    val text = s"$path\n{\n\t\"defaultAction\": \"SCMP_ACT_ERRNO\",\n\t\"syscalls\": []\n}\n"
    val profile = Obj(Vector("defaultAction" -> Str("SCMP_ACT_ERRNO"), "syscalls" -> Arr(Vector.empty)))
    assertEquals(readAnswer(text), Right((path, profile)))
    assert(readAnswer("/usr/share/containers/seccomp.json").isLeft)
    assert(readAnswer("/etc/containers/seccomp.json\nnot json").isLeft)

  test("the profile is one file under the state root, named to podman create by its path, built or refused"):
    val state = Paths.get("/state")
    assertEquals(profileFile(state), Paths.get("/state/seccomp/nesting-none.json"))
    assertEquals(createArgument(state), "--security-opt=seccomp=/state/seccomp/nesting-none.json")
    val root = Files.createTempDirectory("ko-agent-sandbox-seccomp")
    assert(missingReason(root).exists(_.startsWith(s"error: the seccomp profile for --nesting=none is not built: ")))
    assert(missingReason(root).exists(_.contains("Run --build, or --update")))
    Files.createDirectories(profileFile(root).getParent)
    Files.writeString(profileFile(root), "{}")
    assertEquals(missingReason(root), None)
