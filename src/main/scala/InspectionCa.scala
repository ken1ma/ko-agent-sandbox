package agentsandbox.launcher

import java.time.Instant
import agentsandbox.egress.X509Helper

/** The CAs the launcher creates: a workspace's, and each host proxy's. The proxy's X509Helper builds them, and its
  * CertificateHelper parses and checks them. */
object InspectionCa:

  /** `scope` names the CA's owner inside the CA's common name, which X509Helper.MaxCommonNameLength limits. The fixed
    * wording leaves 42 characters, room for a 32-character workspace slug. */
  def create(scope: String, now: Instant = Instant.now(), days: Long = 3650): X509Helper.IssuedCertificate =
    X509Helper.createCa(s"ko-agent-sandbox CA ($scope)", now, days)
