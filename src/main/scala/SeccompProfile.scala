// The seccomp profile a `--nesting=none` session runs under: podman's installed default profile
// with creating a user namespace, joining a namespace and every mount syscall refused, and with the
// syscalls that change a file's extended attributes, ACLs or flags refused too
// (doc/plan-bpf-lsm-cgroup.md, "Attributes, flags and ioctls": the BPF policy holds no hook for
// them, and the filter refuses them by not implementing them). Derived by --build and --update from
// the default the podman server applies, kept under the launcher's state root, and named to
// `podman create` by path, which the server reads (SECURITY.md, "No containers inside the sandbox
// by default").

package agentsandbox.launcher

import java.nio.file.{Files, Path}

import HostCommands.*
import FileHelper.*
import JsonText.Json
import JsonText.Json.*
import LauncherState.*

object SeccompProfile:

  /** `CLONE_NEWUSER` (linux/sched.h). `clone` and `unshare` carry their flags in their first
    * argument on x86_64 and aarch64, the architectures the images build for, so the filter reads
    * them; s390 orders `clone`'s arguments differently and is not supported. */
  val CloneNewUser = 0x10000000L

  private val EPERM = 1
  private val ENOSYS = 38
  private val EOPNOTSUPP = 95

  /** The syscalls that create, attach, alter or remove a mount (Linux v7.1, `scripts/syscall.tbl`;
    * `umount` exists on the 32-bit sub-architectures the default's archMap covers). The whole
    * family, not `mount` and `fsopen` alone: a mount `fsmount` or `open_tree` with `OPEN_TREE_CLONE`
    * returns is usable through its descriptor before `move_mount` attaches it (measured 2026-10-17:
    * a file created through such a detached clone lands in the cloned directory). */
  val MountSyscalls: Vector[String] = Vector(
    "mount", "umount", "umount2", "fsopen", "fsconfig", "fsmount", "fspick", "move_mount", "open_tree",
    "open_tree_attr", "mount_setattr", "pivot_root",
  )

  /** `clone3` carries its flags in a `struct clone_args` a seccomp filter cannot read (a filter sees
    * register values only), so it is answered `ENOSYS`, which callers fall back from: glibc 2.41,
    * the image's, retries with `clone` (`sysdeps/unix/sysv/linux/clone-internal.c`), `posix_spawn`
    * included except with `POSIX_SPAWN_SETCGROUP`, which then fails with `ENOTSUP`; Go calls
    * `clone3` with no fallback only for a launch that sets `SysProcAttr.UseCgroupFD` or
    * `CLONE_NEWTIME` (`src/syscall/exec_linux.go`, `forkAndExecInChild1`). */
  val NamespaceSyscalls: Vector[String] = Vector("clone", "clone3", "unshare", "setns")

  /** The syscalls that set or remove an extended attribute, POSIX ACLs among them (`fs/xattr.c`
    * routes the `system.posix_acl_*` names), `setxattrat` and `removexattrat` (Linux 6.13) included,
    * and `file_setattr` (Linux 6.17), which sets a file's flags and `fsxattr` fields. Answered
    * `ENOTSUP`, the answer the filter's FUSE mount gives, so that `cp -a` drops the attributes
    * silently as it does there (plan, "Attributes, flags and ioctls"). */
  val AttributeSyscalls: Vector[String] = Vector(
    "setxattr", "lsetxattr", "fsetxattr", "setxattrat", "removexattr", "lremovexattr", "fremovexattr", "removexattrat",
    "file_setattr",
  )

  /** Every name the derived profile decides itself: removed from the default's rules, then ruled
    * below. */
  val RefusedNames: Vector[String] = NamespaceSyscalls ++ MountSyscalls ++ AttributeSyscalls

  private def rule(names: Vector[String], action: String, args: Vector[Json], comment: String, errno: Option[Int])
    : Json =
    Obj(
      Vector("names" -> Arr(names.map(Str(_))), "action" -> Str(action))
        ++ errno.map(code => "errnoRet" -> Num(code.toString))
        ++ Vector("args" -> Arr(args), "comment" -> Str(comment)),
    )

  /** `(arg0 & CLONE_NEWUSER) == expected`: `value` is the mask and `valueTwo` the expected value,
    * as `SCMP_CMP_MASKED_EQ` reads them. */
  private def userNamespaceFlag(expected: Long): Json =
    Obj(Vector(
      "index" -> Num("0"), "value" -> Num(CloneNewUser.toString), "valueTwo" -> Num(expected.toString),
      "op" -> Str("SCMP_CMP_MASKED_EQ"),
    ))

  /** The rules added after the default's. `clone` and `unshare` without `CLONE_NEWUSER` are allowed
    * and with it refused with `EPERM`, the refusal `unshare -Ur` and bubblewrap print as "Operation
    * not permitted". `setns` joins a namespace only with `CAP_SYS_ADMIN` over its owner, which the
    * session holds in no namespace but one it created; refused so that a mistake in the two rules
    * above reopens nothing. The attribute syscalls are refused whole. The filesystem ioctls that
    * change a file (`FS_IOC_SETFLAGS`, `FS_IOC_FSSETXATTR`, the ext4, fscrypt, verity and btrfs
    * commands of the plan's row 18) have no rule: libseccomp refuses some commands of a syscall
    * and allows the rest only with the allowed commands spelled as masked prefixes, since an
    * unconditional rule for a syscall clears its argument rules (`src/db.c`, `_db_rule_add`) and
    * a rule holds one comparison per argument (`db_col_rule_add`): 255 allow rules for today's 19
    * commands. The podman machines' shares answer those commands `ENOTTY` themselves (the plan's
    * "Phase 2 on macOS" and "Phase 2 on WSL", `share`), and the rules stay unbuilt for the first
    * version by the user's decision (the plan, "Decisions still open", has what reopens it). */
  val AddedRules: Vector[Json] = Vector(
    rule(
      Vector("clone", "unshare"), "SCMP_ACT_ALLOW", Vector(userNamespaceFlag(0)),
      "ko-agent-sandbox: without CLONE_NEWUSER", None,
    ),
    rule(
      Vector("clone", "unshare"), "SCMP_ACT_ERRNO", Vector(userNamespaceFlag(CloneNewUser)),
      "ko-agent-sandbox: --nesting=none creates no user namespace", Some(EPERM),
    ),
    rule(
      Vector("clone3"), "SCMP_ACT_ERRNO", Vector.empty,
      "ko-agent-sandbox: flags in memory the filter cannot read; callers fall back to clone", Some(ENOSYS),
    ),
    rule(
      "setns" +: MountSyscalls, "SCMP_ACT_ERRNO", Vector.empty,
      "ko-agent-sandbox: --nesting=none joins no namespace and mounts nothing", Some(EPERM),
    ),
    rule(
      AttributeSyscalls, "SCMP_ACT_ERRNO", Vector.empty,
      "ko-agent-sandbox: no xattr, ACL, flag or fsxattr change in a session (SECURITY.md, the seccomp profile)",
      Some(EOPNOTSUPP),
    ),
  )

  /** The default actions under which a syscall no rule names is refused. A name the host's
    * libseccomp does not know, such as `open_tree_attr` on one older than Linux 6.15, is skipped
    * by the runtime (crun, `libcrun/seccomp.c`, unless `LIBCRUN_SECCOMP_FAIL_UNKNOWN_SYSCALL`), and
    * the default action then decides it; a permitting default would let it through. */
  val RefusingDefaultActions: Set[String] =
    Set("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP")

  /**
   * The default profile with every refused name taken out of its rules, a rule left without names
   * dropped, and AddedRules appended; a default whose `defaultAction` permits an unnamed syscall
   * (RefusingDefaultActions has why) is refused, as is one without the field, since a
   * `containers.conf` can name any profile. Taken out rather than overruled by a later rule: libseccomp
   * keeps a syscall's first unconditional rule and silently drops every later rule for that
   * syscall, with arguments or without (`src/db.c`, `_db_rule_add`, "existing filter is at least as
   * large as the new entry"), and the default lists each refused name in its unconditional allow
   * rule. Measured in a default session 2026-10-26: the default's own later `setns` refusal is
   * dropped that way, `setns(-1, 0)` answering the kernel's `EBADF`.
   */
  def derived(default: Json): Either[String, Json] =
    default match
      case Obj(fields) =>
        val action = default.field("defaultAction").collect { case Str(action) => action }
        fields.collectFirst { case ("syscalls", Arr(rules)) => rules } match
          case _ if !action.exists(RefusingDefaultActions.contains) =>
            Left(
              s"its defaultAction is ${action.getOrElse("absent")}, which permits a syscall the host's " +
                s"libseccomp does not know by name; the launcher derives from " +
                RefusingDefaultActions.toVector.sorted.mkString(", "),
            )
          case None => Left("the default profile has no \"syscalls\" array")
          case Some(rules) =>
            val kept = rules.flatMap(withoutRefusedNames)
            Right(Obj(fields.map {
              case ("syscalls", _) => "syscalls" -> Arr(kept ++ AddedRules)
              case other           => other
            }))
      case _ => Left("the default profile is not a JSON object")

  /** The rule without the refused names, or none when nothing is left; a rule naming one syscall
    * through the format's older `name` field counts the same. */
  private def withoutRefusedNames(rule: Json): Option[Json] =
    rule match
      case Obj(fields) =>
        val withoutName = fields.filterNot:
          case ("name", Str(name)) => RefusedNames.contains(name)
          case _                   => false
        val filtered = withoutName.map:
          case ("names", Arr(names)) =>
            "names" -> Arr(names.filterNot { case Str(name) => RefusedNames.contains(name); case _ => false })
          case other => other
        val namesLeft = filtered.exists:
          case ("names", Arr(names)) => names.nonEmpty
          case ("name", Str(_))      => true
          case _                     => false
        Option.when(namesLeft)(Obj(filtered))
      case other => Some(other)

  // ---------------------------------------------------------------------------
  // Reading podman's default and keeping the derived profile
  // ---------------------------------------------------------------------------

  /** Where the derived profile lives under the launcher's state root; a launch names it to the
    * server by this path, which podman's Windows client spells as the machine sees it, as it does
    * a volume's source (`specgenutil`, `ConvertWinMountPath`). Not per workspace: it depends on
    * the podman host alone. */
  def profileFile(stateRoot: Path): Path = stateRoot.resolve("seccomp").resolve("nesting-none.json")

  /** What `podman info` reports as the default profile's path: `containers.conf`'s `seccomp_profile`
    * when set, which may be `unconfined`, else the first of DefaultProfilePaths that exists, else
    * nothing (podman, `libpod/util.go`, `DefaultSeccompPath`). */
  val ReportedPathFormat = "{{.Host.Security.SECCOMPProfilePath}}"

  /** The paths the server tries in this order when `containers.conf` names none. */
  val DefaultProfilePaths: Vector[String] = Vector("/etc/containers/seccomp.json", "/usr/share/containers/seccomp.json")

  /** The files to read, in order: the reported one when it is a path, else the server's defaults.
    * A reported `unconfined` turns the filter off for podman's own default; the session's explicit
    * profile is applied regardless, derived from the installed default. */
  def candidatePaths(reported: String): Vector[String] =
    val path = reported.trim
    if path.startsWith("/") then Vector(path) else DefaultProfilePaths

  /** The first readable candidate: its path on the first line, its content after. The paths are
    * the server's, so each one's directory is bound into a throwaway container of the image, and
    * the script reads it there. `label=disable`, so the read does not depend on what the container
    * type may read of the host's `/etc` and `/usr/share` under SELinux, whose system labels the
    * launcher never changes; the container has no network and reads one file. */
  val ReadScript: String =
    """for p; do
      |  if [ -f "$p" ] && [ -r "$p" ]; then echo "$p"; cat "$p"; exit 0; fi
      |done
      |echo "no readable seccomp profile at $*" >&2
      |exit 3""".stripMargin

  def readDefaultCommand(podman: String, image: String, candidates: Vector[String]): Vector[String] =
    val mountpoints = candidates.indices.map(index => s"/mnt/seccomp/$index")
    val directories = candidates.map(path => Path.of(path).getParent.toString.replace('\\', '/'))
    val binds = directories.zip(mountpoints).map((directory, at) => s"--volume=$directory:$at:ro")
    val files = candidates.zip(mountpoints).map((path, at) => s"$at/${Path.of(path).getFileName}")
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--security-opt=label=disable", "--entrypoint=")
      ++ binds ++ Vector(image) ++ quoteFreeSh(ReadScript, files*)

  /** The path read and the profile it held, from a ReadScript answer. */
  def readAnswer(text: String): Either[String, (String, Json)] =
    text.indexOf('\n') match
      case -1 => Left("the read printed no profile after the path")
      case newline =>
        JsonText.parse(text.substring(newline + 1)).map(json => (text.substring(0, newline), json))

  /** Derives and writes the profile; run by --build and --update once the image exists. */
  def install(podman: String, os: Os, image: String): Unit =
    val reported = run(podman, "info", "--format", ReportedPathFormat)
    if !reported.ok then fail(s"error: podman info did not answer the default seccomp profile's path\n${reported.err}")
    val command = readDefaultCommand(podman, image, candidatePaths(reported.text))
    echoCommand(command)
    val read = run(command*)
    if !read.ok then fail(s"error: could not read podman's default seccomp profile\n${read.err}", read.exit)
    def refused(reason: String): Nothing = fail(s"error: podman's default seccomp profile: $reason")
    val (source, default) = readAnswer(read.text).fold(refused, identity)
    val profile = derived(default).fold(refused, identity)
    val file = profileFile(stateRoot(os))
    createPrivateDirectories(file.getParent)
    writePrivate(file, JsonText.render(profile) + "\n")
    System.err.println(s"seccomp profile for --nesting=none: $file, derived from $source")

  /** Why a `--nesting=none` launch cannot proceed, or None: the profile is derived by the build
    * actions, and a launch without it would run under podman's default, the weaker boundary; one
    * an earlier build derived lacks the rules this build adds (AddedRules), which the BPF backend's
    * protections rest on, so it is refused too. */
  def missingReason(stateRoot: Path): Option[String] =
    val file = profileFile(stateRoot)
    if !Files.isRegularFile(file) then
      Some(
        s"""error: the seccomp profile for --nesting=none is not built: $file
           |Run --build, or --update, which derive it from podman's default profile.""".stripMargin,
      )
    else
      val content =
        try Files.readString(file)
        catch case ex: java.io.IOException => ex.getMessage
      staleReason(JsonText.parse(content).toOption).map(reason =>
        s"""error: the seccomp profile for --nesting=none, $file, $reason
           |Run --build, or --update, which derive it again.""".stripMargin,
      )

  /** Why a profile is not this build's, or None: every rule of AddedRules must be among its rules,
    * as `derived` appends them, in their order. */
  def staleReason(profile: Option[Json]): Option[String] =
    profile match
      case None => Some("is not a JSON profile")
      case Some(json) =>
        json.field("syscalls") match
          case Some(Arr(rules)) =>
            Option.when(!rules.containsSlice(AddedRules))("lacks the rules this launcher's build adds")
          case _ => Some("has no \"syscalls\" array")

  /** The `podman create` argument naming the profile. */
  def createArgument(stateRoot: Path): String = s"--security-opt=seccomp=${profileFile(stateRoot)}"
