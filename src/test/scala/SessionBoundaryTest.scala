// The boundary as a session sees it. ProxyContainerTest checks the proxy's runtime separately.
//
// It runs itself: `sbt testFull` from inside a session executes it, and `assume` skips it
// everywhere else, so there is no separate command to remember. KO_AGENT_SANDBOX_EGRESS_RULESET is
// the condition because the launcher sets it for every session and nothing else does. The workspace root
// is the working directory: the launcher starts the session there, at the workspace root's own path.
//
// The network checks drive `curl` and `getent` as processes rather than Java's own HTTP and TLS:
// the proxy meets those clients in practice, and a JDK client would be testing a different one.
// The one exception is the query to the network's own resolver: no program in the image sends a
// DNS query to a chosen server.

package agentsandbox.launcher

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path, Paths, StandardOpenOption}
import scala.jdk.CollectionConverters.*

import HostCommands.*
import FileHelper.*

class SessionBoundaryTest extends munit.FunSuite:

  private val insideSession = env("KO_AGENT_SANDBOX_EGRESS_RULESET").isDefined

  private val workspace = Paths.get("").toAbsolutePath

  private def inSession(): Unit =
    assume(insideSession, "not inside a sandbox session")

  private val ProxyVariables = Vector("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")

  /** HostCommands.run with the environment altered, which it deliberately does not expose. */
  private def runWithout(removed: Seq[String], command: String*): Run =
    val builder = ProcessBuilder(command*)
    removed.foreach(builder.environment().remove)
    val process = builder.start()
    process.getOutputStream.close()
    var err: Array[Byte] = Array.emptyByteArray
    val draining = Thread(() => err = process.getErrorStream.readAllBytes())
    draining.start()
    val out = process.getInputStream.readAllBytes()
    draining.join()
    Run(process.waitFor(), out, String(err, StandardCharsets.UTF_8).stripLineEnd)

  private def curl(args: String*): Run =
    run((Vector("curl", "-sS", "--max-time", "25") ++ args)*)

  /** The HTTP status, or "000" when the connection never became one — which is what a refusal at
    * the CONNECT checks looks like, as opposed to a 403 handed back inside a tunnel. */
  private def status(args: String*): String =
    curl((Vector("-o", "/dev/null", "-w", "%{http_code}") ++ args)*).text.trim

  /** `EPERM` specifically — the filter's policy denial — rather than merely "an error", which is
    * the same distinction the mounted Rust suites draw. Java reports `EPERM` as a bare
    * `FileSystemException`; `AccessDeniedException` is `EACCES`, a different answer that would mean
    * the tree was laid out differently than the test assumed. */
  private def deniedByFilter(what: String)(thunk: => Any): Unit =
    val refusal = intercept[java.nio.file.FileSystemException](thunk)
    assert(
      refusal.getMessage.contains("Operation not permitted"),
      s"$what failed with '${refusal.getMessage}', but not as a policy denial (EPERM)",
    )

  /** One DNS A query over UDP, answered as (response code, answer count). */
  private def queryA(server: java.net.InetAddress, name: String): (Int, Int) =
    val header = Array[Byte](0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0) // recursion desired, one question
    val labels = name.split('.').flatMap(label => label.length.toByte +: label.getBytes(StandardCharsets.US_ASCII))
    val query = header ++ labels ++ Array[Byte](0, 0, 1, 0, 1) // root, type A, class IN
    val socket = java.net.DatagramSocket()
    try
      socket.setSoTimeout(5000)
      socket.send(java.net.DatagramPacket(query, query.length, server, 53))
      val response = new Array[Byte](512)
      socket.receive(java.net.DatagramPacket(response, response.length))
      (response(3) & 0x0f, (response(6) & 0xff) << 8 | response(7) & 0xff)
    finally socket.close()

  private def procLines(path: String): Vector[String] =
    Files.readAllLines(Paths.get(path)).asScala.toVector

  private def field(status: String, name: String): String =
    procLines("/proc/self/status")
      .find(_.startsWith(name))
      .map(_.split("\\s+").last)
      .getOrElse(s"($name absent from $status)")

  /** The kernel writes a space, tab, newline or backslash in a mountinfo path as `\NNN` octal
    * (`show_mountinfo`, `mangle_path`), so a workspace path holding one matches only decoded. */
  private def unescapeMountinfo(field: String): String =
    "\\\\([0-7]{3})".r.replaceAllIn(
      field,
      found => java.util.regex.Matcher.quoteReplacement(Integer.parseInt(found.group(1), 8).toChar.toString),
    )

  private def mountPoints: Vector[String] =
    procLines("/proc/self/mountinfo").map(line => unescapeMountinfo(line.split(" ")(4)))

  private def mountOptions(at: String): Option[String] =
    procLines("/proc/self/mountinfo").collectFirst {
      case line if unescapeMountinfo(line.split(" ")(4)) == at => line.split(" ")(5)
    }

  test("a mountinfo path is matched decoded: the kernel writes its spaces and backslashes as octal"):
    assertEquals(unescapeMountinfo("/work/my\\040project\\134x"), "/work/my project\\x")
    assertEquals(unescapeMountinfo("/plain/path"), "/plain/path")

  test("the container is the unprivileged one the image declares"):
    inSession()
    assertEquals(run("id", "-u").text, "65532")
    assertEquals(run("id", "-g").text, "65532")
    assertEquals(field("/proc/self/status", "NoNewPrivs"), "1")
    assertEquals(field("/proc/self/status", "Seccomp"), "2")

    // "All capabilities dropped" is the wrong assertion: the nesting opt-in grants exactly one, so
    // demanding an empty set fails a correctly configured nested session while missing the failure
    // that matters — a capability arriving without the variable that grants it.
    val nesting = env(AgentSandboxLauncher.NestingVariable).getOrElse("none")
    val expectedCapabilities = nesting match
      case "none" | "user-namespace" => "0000000000000000"
      case "same-uid"                => "0000000000040000" // cap_sys_chroot, and only that
      case other                     => fail(s"unknown nesting mode $other")
    assertEquals(field("/proc/self/status", "CapEff"), expectedCapabilities, s"nesting=$nesting")

    assert(mountOptions("/").exists(_.startsWith("ro")), "the root filesystem is writable")
    assertEquals(Files.readString(Paths.get("/sys/fs/cgroup/pids.max")).trim, "2048")

    // A memory limit on every launch, explicit or the machine-derived default, and no swap beyond
    // it.
    val memoryLimit = Files.readString(Paths.get("/sys/fs/cgroup/memory.max")).trim
    assertNotEquals(memoryLimit, "max")
    assertEquals(Files.readString(Paths.get("/sys/fs/cgroup/memory.swap.max")).trim, "0")

  /** Each syscall SeccompProfile decides, called with arguments the kernel answers before its
    * capability check where it has such a check: `ENOENT`, `EINVAL` or `EBADF` from the kernel,
    * `EPERM` or `ENOSYS` from the filter (measured on the machine's kernel 7.2.5 under podman's
    * default profile, 2026-10-26). `fsopen`, `fspick` and `move_mount` check the capability first
    * and answer `EPERM` either way. The `clone` with `CLONE_NEWUSER` is a fork when allowed, and
    * the child exits at once. Then a thread and a child process, which the profile must leave
    * working. */
  private val SyscallProbe: String =
    """import ctypes, errno, os, subprocess, threading
      |libc = ctypes.CDLL(None, use_errno=True)
      |libc.syscall.restype = ctypes.c_long
      |nr = {'x86_64': dict(clone=56, unshare=272, setns=308, mount=165, umount2=166, pivot_root=155),
      |      'aarch64': dict(clone=220, unshare=97, setns=268, mount=40, umount2=39, pivot_root=41)}[os.uname().machine]
      |nr.update(clone3=435, open_tree=428, move_mount=429, fsopen=430, fsconfig=431, fsmount=432, fspick=433,
      |          mount_setattr=442, open_tree_attr=467, file_setattr=468)
      |def answer(name, *args):
      |    ctypes.set_errno(0)
      |    r = libc.syscall(ctypes.c_long(nr[name]), *[ctypes.c_long(a) if isinstance(a, int) else a for a in args])
      |    print(name, 'ok' if r >= 0 else errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno())))
      |    return r
      |CLONE_NEWUSER, SIGCHLD = 0x10000000, 17
      |pid = answer('clone', CLONE_NEWUSER | SIGCHLD, 0, 0, 0, 0)
      |if pid == 0: os._exit(0)
      |if pid > 0: os.waitpid(pid, 0)
      |answer('unshare', CLONE_NEWUSER)
      |answer('clone3', None, 0)
      |answer('setns', -1, 0)
      |answer('mount', b'none', b'/nonexistent-ko-agent-sandbox', b'tmpfs', 0, None)
      |answer('umount2', b'/tmp', 0xffff)
      |answer('pivot_root', b'/nonexistent-ko-agent-sandbox', b'/nonexistent-ko-agent-sandbox')
      |answer('open_tree', -1, b'', 0xffff)
      |answer('move_mount', -1, b'', -1, b'', 0xffff)
      |answer('fsopen', b'tmpfs', 0xffff)
      |answer('fsconfig', -1, 0, None, None, 0)
      |answer('fsmount', -1, 0xffff, 0)
      |answer('fspick', -1, b'', 0xffff)
      |answer('mount_setattr', -1, b'', 0xffff, None, 0)
      |answer('open_tree_attr', -1, b'', 0xffff, None, 0)
      |# The attribute syscalls (SeccompProfile.AttributeSyscalls), on a file of the container's own
      |# filesystem, where the kernel itself would admit each; an ioctl stays with the kernel.
      |import fcntl, tempfile
      |with tempfile.NamedTemporaryFile(dir=os.path.expanduser('~')) as f:
      |    def attr(name, call):
      |        try:
      |            call()
      |            print(name, 'ok')
      |        except OSError as ex:
      |            print(name, errno.errorcode.get(ex.errno, str(ex.errno)))
      |    attr('setxattr', lambda: os.setxattr(f.name, 'user.ko', b'v'))
      |    attr('fsetxattr', lambda: os.setxattr(f.fileno(), 'user.ko', b'v'))
      |    attr('removexattr', lambda: os.removexattr(f.name, 'user.ko'))
      |    attr('ioctl_fionread', lambda: fcntl.ioctl(f.fileno(), 0x541b, b'\0' * 4))
      |    answer('file_setattr', -1, b'', None, 0, 0)
      |threading.Thread(target=lambda: None).start()
      |print('child', subprocess.run(['true']).returncode)
      |""".stripMargin

  test("under --nesting=none no user namespace is created and nothing is mounted; processes still start"):
    inSession()
    val nesting = env(AgentSandboxLauncher.NestingVariable).getOrElse("none")
    val unshared = run("unshare", "-Ur", "true")
    if nesting != "none" then assertEquals(unshared.exit, 0, s"unshare -Ur under $nesting: ${unshared.err}")
    else
      assert(unshared.err.contains("Operation not permitted"), s"unshare -Ur: exit ${unshared.exit}, '${unshared.err}'")
      val probe = run("python3", "-I", "-c", SyscallProbe)
      assertEquals(probe.exit, 0, probe.err)
      val answers = probe.text.linesIterator.map(_.split(" ", 2)).map(parts => parts(0) -> parts(1)).toMap
      // The kernel's own answer to each probe's arguments is another errno (SyscallProbe), so these
      // `EPERM`s are the filter's. `umount` has no syscall on these architectures.
      val filtered = Vector(
        "clone", "unshare", "setns", "mount", "umount2", "pivot_root", "open_tree", "fsconfig", "fsmount",
        "mount_setattr",
      )
      filtered.foreach(name => assertEquals(answers.get(name), Some("EPERM"), name))
      assertEquals(answers.get("clone3"), Some("ENOSYS"))
      // Capability-first: the kernel answers `EPERM` to any arguments without CAP_SYS_ADMIN, so a
      // session cannot tell the filter's refusal from the kernel's. They sit in the one rule whose
      // other names the assertions above prove installed (SeccompProfile.AddedRules), and the
      // derivation test proves the rule names them.
      Vector("fsopen", "fspick", "move_mount").foreach(name => assertEquals(answers.get(name), Some("EPERM"), name))
      // `open_tree_attr` (Linux 6.15): `ENOSYS` where libseccomp does not know the name and the
      // default action refuses it, `EPERM` where it does.
      assert(Set("EPERM", "ENOSYS").exists(answers.get("open_tree_attr").contains), answers.get("open_tree_attr"))
      // The attribute syscalls: `ENOTSUP`, which the kernel never answers for a `user.` xattr on the
      // container's own filesystem; an ioctl reaches the kernel (FIONREAD on a regular file: the
      // filesystem's own answer, not the filter's). `file_setattr` (Linux 6.17): `ENOSYS` where
      // libseccomp lacks the name.
      Vector("setxattr", "fsetxattr", "removexattr").foreach: name =>
        assert(Set("ENOTSUP", "EOPNOTSUPP").exists(answers.get(name).contains), s"$name: ${answers.get(name)}")
      assert(answers.contains("ioctl_fionread"), "the ioctl probe ran")
      val fileSetattr = answers.get("file_setattr")
      assert(Set("ENOTSUP", "EOPNOTSUPP", "ENOSYS").exists(fileSetattr.contains), fileSetattr)
      assertEquals(answers.get("child"), Some("0"))
      val thread = Thread(() => ())
      thread.start()
      thread.join()

  test("the network has one interface and no route off it"):
    inSession()
    val interfaces = procLines("/proc/net/dev").drop(2).count(!_.trim.startsWith("lo:"))
    assertEquals(interfaces, 1, "more than the one internal network is attached")

    // The structural reason the proxy variables are advisory: the internal network has no gateway,
    // so nothing outside its /24 is addressable at all.
    val defaultRoutes = procLines("/proc/net/route").drop(1).count(_.split("\\s+")(1) == "00000000")
    assertEquals(defaultRoutes, 0, "a default route exists")

    assert(
      Files.readString(Paths.get("/etc/hosts")).linesIterator.exists(_.endsWith("\tegress-proxy")),
      "the proxy is not named in /etc/hosts, so it is being learned from a resolver",
    )

    // NO_PROXY names exemptions rather than a proxy; every variable that does name one must name
    // this run's.
    val foreign = System.getenv().asScala.toMap
      .filter((name, _) => name.toLowerCase.endsWith("proxy"))
      .filterNot((name, _) => name.equalsIgnoreCase("NO_PROXY"))
      .filterNot((_, value) => value.contains("egress-proxy:3128"))
    assertEquals(foreign, Map.empty[String, String])

  test("unsetting the proxy variables restores nothing"):
    inSession()
    assert(!runWithout(ProxyVariables, "curl", "-sS", "--max-time", "10", "https://pypi.org/").ok)
    assert(!runWithout(ProxyVariables, "curl", "-sS", "--max-time", "10", "https://1.1.1.1/").ok)

    // The stricter check: the failure is immediate and structural, not a timeout.
    val reached =
      try
        val socket = java.net.Socket()
        try socket.connect(java.net.InetSocketAddress("1.1.1.1", 443), 5000)
        finally socket.close()
        "connected"
      catch case ex: java.io.IOException => ex.getMessage
    assertEquals(reached, "Network is unreachable")

    Vector("example.com", "secret-payload.attacker.example").foreach: name =>
      assert(!run("getent", "hosts", name).ok, s"$name resolved through the resolvers resolv.conf names")

  test("the network's own resolver answers the run's names and no external one"):
    inSession()
    // getent never asks this resolver: resolv.conf does not name it. The on-link route is the
    // network, in little-endian hex; the resolver listens on its first address.
    val network = procLines("/proc/net/route").drop(1).map(_.split("\\s+")(1)).find(_ != "00000000")
      .getOrElse(fail("no on-link route"))
    val firstAddress = Integer.reverseBytes(Integer.parseUnsignedInt(network, 16)) + 1
    val resolver = java.net.InetAddress.getByAddress(java.nio.ByteBuffer.allocate(4).putInt(firstAddress).array())

    // The run's own name must resolve, so the NXDOMAIN answers below come from the network's name
    // service rather than from another listener at that address.
    val ownName = Files.readString(Paths.get("/etc/hostname")).trim
    val (ownCode, ownAnswers) = queryA(resolver, ownName)
    assert(ownCode == 0 && ownAnswers > 0, s"$resolver does not answer this container's name")

    // example.com exists, so a resolver that forwarded it would answer.
    Vector("example.com", "secret-payload.attacker.example").foreach: name =>
      assertEquals(queryA(resolver, name), (3, 0), s"$resolver did not answer NXDOMAIN for $name")

  test("the CONNECT checks refuse everything but a listed host on 443"):
    inSession()
    // A refusal here fails the CONNECT rather than answering inside a tunnel, so curl reports it
    // as an error with the proxy's status instead of as an HTTP code.
    Vector(
      "https://unlisted.invalid/",  // reserved (RFC 6761): never an allowed host
      "https://8.8.8.8/",
      "https://169.254.169.254/",
      "https://10.0.0.1/",
      "https://pypi.org:8443/"
    ).foreach: url =>
      val attempt = curl("-o", "/dev/null", url)
      assert(!attempt.ok, s"$url was not refused")
      assert(attempt.err.contains("403"), s"$url was refused, but not by the proxy: ${attempt.err}")

    assertEquals(status("http://pypi.org/"), "400", "plain http reached a tunnel")

  test("the two treatments are told apart by the certificate each host presents"):
    inSession()
    // The decisive in-session test for "a tunnel host is still opaque": an
    // inspected host presents a leaf this workspace's CA signed, an opaque one the origin's own chain.
    val ca = run("openssl", "x509", "-noout", "-subject", "-in", "/etc/ko-agent-sandbox/egress-proxy-ca.crt")
      .text.stripPrefix("subject=").trim

    // curl indents its certificate lines under the `*` marker, and by more than one space, so this
    // keys on the field name rather than on the format of the prefix.
    def issuer(host: String): String =
      curl("-v", "-o", "/dev/null", s"https://$host/").err.linesIterator
        .map(_.trim)
        .collectFirst:
          case line if line.startsWith("*") && line.contains("issuer:") =>
            line.substring(line.indexOf("issuer:") + "issuer:".length).trim
        .getOrElse("(no issuer line)")

    Vector("pypi.org", "github.com").foreach: host =>
      assertEquals(issuer(host), ca, s"$host is not inspected")
    Vector("api.anthropic.com", "chatgpt.com").foreach: host =>
      assertNotEquals(issuer(host), ca, s"$host was inspected; a tunnel host must stay opaque")

  test("an inspected tunnel permits reading and refuses writing"):
    inSession()
    assertEquals(status("https://docs.python.org/3/"), "200")
    assertEquals(status("-X", "PUT", "https://docs.python.org/3/"), "403")
    assertEquals(status("https://github.com/"), "200")
    assertEquals(status("-X", "POST", "https://github.com/"), "403")
    assertEquals(
      status("https://github.com/git/git.git/info/refs?service=git-upload-pack"), "200",
      "fetch ref discovery",
    )
    assertEquals(
      status("https://github.com/o/r.git/info/refs?service=git-receive-pack"), "403",
      "push ref discovery",
    )
    assertEquals(status("-X", "POST", "https://api.github.com/graphql"), "403")
    assertEquals(status("-X", "POST", "https://github.com/o/r.git/info/lfs/objects/batch"), "403")
    // No line grants a POST at npm's audit endpoint, so it is a POST like any other.
    assertEquals(
      status("-X", "POST", "-H", "Content-Type: application/json", "-d", "{}",
             "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"), "403",
      "npm's audit endpoint, no line granting its POST",
    )
    assertEquals(status("-X", "POST", "-d", "{}", "https://registry.npmjs.org/lodash"), "403")

  test("a refusal says what to do next, in the words curl, git and the check print"):
    inSession()
    // RefusalAdvice's rows as the programs show them: curl prints a 403's body
    // as it is, git prints a text/plain body as `remote:` lines, and ko-sandbox-egress-check is the
    // only reader of a failed CONNECT's body.
    import agentsandbox.egress.RefusalAdvice
    def body(args: String*): String = curl(args*).text
    assert(body("-X", "PUT", "https://docs.python.org/3/").contains(RefusalAdvice.methodNotGranted))
    assert(body("-X", "POST", "-d", "{}", "https://api.github.com/graphql").contains(RefusalAdvice.graphql))
    assert(
      body("-X", "POST", "-d", "{}", "https://github.com/o/r.git/info/lfs/objects/batch")
        .contains(RefusalAdvice.lfsBatchGithub),
    )

    // A ref deletion needs no local commit and still starts with receive-pack discovery.
    val repo = Files.createTempDirectory("push-probe")
    try
      assert(run("git", "-C", repo.toString, "init", "-q").ok)
      val push = run("git", "-C", repo.toString, "push", "https://github.com/o/r.git", ":refs/heads/x")
      assert(!push.ok)
      assert(push.err.contains(s"remote: ${RefusalAdvice.gitPush}"), push.err)
    finally
      deleteRecursively(repo)

    val refused = run("ko-sandbox-egress-check", "unlisted.invalid")
    assertEquals(refused.exit, 1, refused.err)
    assert(refused.text.contains("403"), refused.text)
    assert(refused.text.contains("Proxy-Status: ko-agent-egress-proxy; error=http_request_denied"), refused.text)
    assert(
      refused.text.contains(
        RefusalAdvice.hostNotAllowed("unlisted.invalid", agentsandbox.egress.RulesetHelper.DefaultProfile),
      ),
      refused.text,
    )
    val allowed = run("ko-sandbox-egress-check", "api.github.com")
    assertEquals(allowed.exit, 0, allowed.err)
    assert(allowed.text.contains("HEAD / -> HTTP/1.1 "), allowed.text)
    // A host granted below / alone, when the session's providers list one: the proxy refuses the
    // HEAD / inside the tunnel, and the check reports that as the refusal it is.
    val grants = raw"allow https://([^/\s]+)(/\S*)".r
      .findAllMatchIn(env("KO_AGENT_SANDBOX_EGRESS_RULESET").getOrElse(""))
      .map(found => found.group(1) -> found.group(2))
      .toVector
    grants.map(_._1).distinct.find(host => !grants.contains(host -> "/")).foreach: host =>
      val inner = run("ko-sandbox-egress-check", host)
      assertEquals(inner.exit, 1, inner.text)
      assert(inner.text.contains(s"CONNECT $host:443: 200; HEAD /: HTTP/1.1 403"), inner.text)
      assert(inner.text.contains("Proxy-Status: ko-agent-egress-proxy; error=http_request_denied"), inner.text)

  test("a JVM reaches an allowed host with no proxy variable of its own"):
    inSession()
    // Driven as a program rather than asserted against the mounted file, because what matters is
    // that the default ProxySelector acts on it — and that it does so without setting a system
    // property (ko-sandbox-jdk-use-proxy has why).
    val probe = Files.createTempDirectory("jvm-proxy-probe")
    try
      val source = probe.resolve("Probe.java")
      Files.writeString(
        source,
        """import java.net.*;
          |public class Probe { public static void main(String[] a) throws Exception {
          |  URI target = URI.create("https://repo1.maven.org/maven2/");
          |  var connection = (HttpURLConnection) target.toURL().openConnection();
          |  connection.setConnectTimeout(20000);
          |  connection.setReadTimeout(20000);
          |  System.out.println(ProxySelector.getDefault().select(target)
          |    + " property=" + System.getProperty("https.proxyHost")
          |    + " status=" + connection.getResponseCode());
          |}}
          |""".stripMargin
      )
      val answer = run("java", source.toString)
      assert(answer.ok, s"the probe did not run: ${answer.err}")
      assert(answer.text.contains("status=200"), s"a JVM could not reach the host: ${answer.text}")
      assert(
        answer.text.contains("property=null"),
        s"the proxy arrived as a system property, which prints a banner on every JVM: ${answer.text}",
      )
    finally deleteRecursively(probe)

  test("the image JDK's trust store holds this workspace's CA beside every root it shipped"):
    inSession()
    // Dropping a shipped root would be the silent half of preparing the store wrong: the sandbox
    // would keep working until a request needed a public CA. The shipped store is under the
    // mount, so the check is for a root every Temurin ships and for a count no per-workspace
    // addition could reach on its own.
    val listing = run("keytool", "-list", "-cacerts", "-storepass", "changeit")
    assert(listing.ok, s"keytool could not read the mounted store: ${listing.err}")
    val aliases = listing.text.linesIterator.filter(_.contains("trustedCertEntry")).map(_.takeWhile(_ != ',')).toVector
    assert(aliases.contains("ko-agent-sandbox-egress"), "this workspace's CA is not in the store")
    assert(aliases.exists(_.contains("isrgrootx1")), s"a shipped root is gone: ${aliases.take(5)}")
    assert(aliases.size > 100, s"the store holds ${aliases.size} roots, not the image's set")

  test("npm refuses package versions younger than seven days, and uv has no window"):
    inSession()
    // SECURITY.md, "The supply chain". This project has no `.npmrc` and no `[tool.uv]` table, so
    // the image's layer is what each reads.
    assertEquals(run("npm", "config", "get", "min-release-age").text, "7")
    // uv logs the cutoff it solves with at -vv; an empty requirement list on stdin needs no index.
    val solve = run("uv", "-vv", "--offline", "pip", "compile", "--no-cache", "-")
    assert(solve.ok, s"uv could not solve an empty requirement list: ${solve.err}")
    assert(!solve.err.contains("Solving with exclude-newer"), s"uv solves under a window:\n${solve.err}")

  test("a git host serves an anonymous clone"):
    inSession()
    // Under /tmp, never the workspace: cloning into it is refused by the filter itself,
    // which would make this a test of the wrong boundary.
    val into = Files.createTempDirectory("clone-probe")
    try
      val clone = run(
        "git", "clone", "--quiet", "--depth", "1",
        "https://github.com/octocat/Hello-World.git", into.resolve("repo").toString,
      )
      assert(clone.ok, s"an anonymous clone failed: ${clone.err}")
    finally deleteRecursively(into)

  /** The workspace mount's filesystem type and source from mountinfo: the filter mounts as `fuse`
    * from `ko-agent-fs` (fs.rs, `MountOption::FSName`); the podman machine's share, which the BPF
    * backend mounts itself, is `virtiofs` or `9p`. The share's magic is FUSE's too on macOS, so
    * `stat -f %T` cannot tell them apart. */
  private def workspaceMount: Option[(String, String)] =
    procLines("/proc/self/mountinfo").collectFirst {
      case line if unescapeMountinfo(line.split(" ")(4)) == workspace.toString =>
        val after = line.split(" - ")(1).split(" ")
        (after(0), unescapeMountinfo(after(1)))
    }

  test("the workspace is writable, and its Git entries are not, under the filter or the policy"):
    inSession()
    val mount = workspaceMount.getOrElse(fail(s"$workspace is not a mount point in /proc/self/mountinfo"))
    val filtered = mount == ("fuse", "ko-agent-fs")

    val work = Files.createTempDirectory(workspace, ".boundary-test-")
    try
      Files.writeString(work.resolve("ordinary"), "x")
      assert(Files.exists(work.resolve("ordinary")), s"$workspace is not writable")

      // A writable workspace mounted from elsewhere is the BPF backend's share
      // (--workspace=live,bpf, the other live mode). The policy lets an empty
      // `.git` directory be made at any depth and refuses the first entry under it; the filter
      // refuses the directory itself (SECURITY.md, "The BPF backend").
      val deep = Files.createDirectories(work.resolve("deep/nested"))
      Vector(work, deep).foreach: at =>
        if filtered then
          deniedByFilter(s"creating .git under ${at.getFileName}"):
            Files.createDirectory(at.resolve(".git"))
        else
          val dotGit = Files.createDirectory(at.resolve(".git"))
          deniedByFilter(s"creating .git/HEAD under ${at.getFileName}"):
            Files.writeString(dotGit.resolve("HEAD"), "ref: refs/heads/main\n")
          Files.delete(dotGit)

      val config = workspace.resolve(".git/config")
      if Files.exists(config) then
        // Appending nothing rather than truncating: the question is whether a write is
        // permitted, and asking it must not perform one on the user's own repository.
        deniedByFilter("opening this repository's .git/config for writing"):
          Files.newOutputStream(config, StandardOpenOption.APPEND).close()
    finally deleteRecursively(work)

  test("the session cannot write the boundary directory governing the next launch"):
    inSession()
    // Which mechanism refuses depends on the session's workspace mode: the filter's reserved-name
    // rule answers EPERM for `.ko-agent-sandbox` at any depth, creation of the directory itself
    // included; --workspace=read-only's read-only tree answers EROFS. Either way the write must
    // fail — a session able to create or edit the directory writes the rules governing the
    // *next* session (SECURITY.md).
    val boundaryDir = workspace.resolve(".ko-agent-sandbox")
    val probe =
      if Files.isDirectory(boundaryDir) then boundaryDir.resolve("probe")
      else boundaryDir
    val refused = intercept[java.nio.file.FileSystemException]:
      if probe == boundaryDir then Files.createDirectory(boundaryDir): Unit
      else Files.newOutputStream(probe).close()
    assert(
      refused.getMessage.contains("Operation not permitted")
        || refused.getMessage.contains("Read-only file system"),
      s"the boundary write was refused with '${refused.getMessage}', not by a boundary mechanism",
    )

  test("no host path is mounted into the session beyond the launcher's set"):
    inSession()
    // Existence proves nothing — the session's home is its own writable volume, and any program it
    // runs may create `.config` there. What matters is whether a host path was *mounted*.
    val home = env("HOME").getOrElse("/home/nonroot")
    Vector(s"$home/.ssh", s"$home/.aws", s"$home/.config",
           "/var/run/docker.sock", "/run/podman/podman.sock")
      .foreach(path => assert(!mountPoints.contains(path), s"$path is mounted into the session"))

    // The workspace root at its own path, and the guard mounts beneath it.
    val quotedWorkspace = java.util.regex.Pattern.quote(workspace.toString)
    val expected =
      raw"^/$$|^/(proc|sys|dev|run|tmp|var/tmp|home/nonroot)($$|/)|^$quotedWorkspace($$|/)".r.unanchored
    // `/etc/ssl/certs` covers two mounts, not one: the PEM bundle, and the merged JDK trust store —
    // which the launcher mounts at `$JAVA_HOME/lib/security/cacerts` (JdkTrust) but which ends up
    // here, because Temurin's Debian packaging symlinks that path to
    // /etc/ssl/certs/adoptium/cacerts and podman resolves a bind target before mounting it.
    // The --claude-plugin-dir mounts: the generated marketplace root, each plugin under it, the drop-in.
    val pluginMounts = raw"^/etc/claude-code/(host-plugins($$|/)|managed-settings\.d/50-host-plugins\.json$$)"
    val alsoExpected =
      (raw"^/etc/(hosts|hostname|resolv\.conf)$$|^/etc/(ko-agent-sandbox|ssl/certs)($$|/)|" + pluginMounts).r.unanchored
    // The JDK's proxy configuration, the other half of jdkMounts' technique. Unlike `cacerts`
    // this one is a real file, so its mount stays where the launcher put it and is named from
    // JAVA_HOME rather than matched by a fixed prefix.
    val netProperties = env("JAVA_HOME").map(_ + "/conf/net.properties")
    val unexpected = mountPoints.distinct.filterNot: at =>
      expected.matches(at) || alsoExpected.matches(at) || netProperties.contains(at)
    assertEquals(unexpected, Vector.empty[String], "a mount outside the launcher's set is present")

  test("a plugin the launch named is mounted read-only where the managed drop-in says, in place"):
    inSession()
    val dropIn = Paths.get(ClaudePlugins.DropInPath)
    assume(Files.exists(dropIn), s"the launch named no ${ClaudePlugins.OptionName}")
    def readOnly(at: String): Boolean = mountOptions(at).exists(_.split(',').contains("ro"))
    assert(readOnly(ClaudePlugins.DropInPath), "the drop-in is not a read-only mount")
    assert(readOnly(ClaudePlugins.MountRoot), "the marketplace root is not a read-only mount")
    val names = """"([^"]+)@host": true""".r.findAllMatchIn(Files.readString(dropIn)).map(_.group(1)).toVector
    assert(names.nonEmpty, "the drop-in enables no plugin")
    val marketplace = Files.readString(Paths.get(ClaudePlugins.MountRoot, ClaudePlugins.MarketplaceFile))
    names.foreach: name =>
      assert(marketplace.contains(s""""source": "./$name""""), s"the marketplace does not list $name in place")
      val at = s"${ClaudePlugins.MountRoot}/$name"
      assert(readOnly(at), s"$name is not a read-only mount of its own")
      assert(Files.isRegularFile(Paths.get(at, ClaudePlugins.ManifestFile)), s"$name has no manifest at $at")
      val refused = intercept[java.nio.file.FileSystemException]:
        Files.newOutputStream(Paths.get(at, "probe")).close()
      assert(refused.getMessage.contains("Read-only file system"), s"a write under $at: '${refused.getMessage}'")

  test("no private key is mounted into the session"):
    inSession()
    // The certificate this session trusts is public by construction; the key that signs with it
    // stays on the host.
    //
    // Listed rather than walked, and every entry accounted for: a mount whose host source the user
    // removed mid-session leaves the name in place but unresolvable, which a walk reports as an
    // opaque UncheckedIOException. Naming it is the same diagnosis the boundary-directory test above
    // gives, and refusing to skip it is what keeps this assertion about every file that is there.
    val entries = directoryEntries(Paths.get("/etc/ko-agent-sandbox"))
    val unresolvable = entries.filterNot(Files.exists(_))
    assertEquals(
      unresolvable, Vector.empty[Path],
      "mounted but does not resolve: the host source was removed mid-session",
    )
    val material = entries
      .filter(Files.isRegularFile(_))
      .filter(path => Files.readString(path).contains("PRIVATE KEY"))
    assertEquals(material, Vector.empty[Path])
