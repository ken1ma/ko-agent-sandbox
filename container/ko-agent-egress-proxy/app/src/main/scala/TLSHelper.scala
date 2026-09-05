package agentsandbox.egress

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, EOFException, InputStream}
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.security.{KeyFactory, KeyStore, PrivateKey, PublicKey, Signature}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.util.{Base64, Locale}
import javax.net.ssl.{KeyManagerFactory, SNIHostName, SNIServerName, SSLContext, SSLSocket}
import scala.annotation.tailrec
import scala.jdk.CollectionConverters.*
import scala.util.control.NonFatal

import IPAddrHelper.normalizeHost

object TLSHelper:

  def validateTlsIdentity(
    connectHost: String,
    hello: TlsClientHello,
  ): Unit =
    if hello.echPresent then
      throw PolicyViolation("encrypted ClientHello", RefusalAdvice.clientHello)

    val sni =
      hello.serverName match
        case Some(raw) =>
          try normalizeHost(raw)
          catch
            case ex: BadRequest =>
              throw PolicyViolation(s"invalid TLS SNI: ${ex.getMessage}", RefusalAdvice.clientHello)

        case None =>
          throw PolicyViolation("TLS ClientHello has no SNI", RefusalAdvice.clientHello)

    if sni != connectHost then
      throw PolicyViolation(s"SNI $sni differs from target", RefusalAdvice.clientHello)

  /**
   * The MITM, and the one place holding a private key. Under the finite profiles that is the
   * leaf's only: the CA key never enters this container, so nothing in it can issue a
   * certificate for a name the launcher did not already choose. Under allow-unless-denied it is
   * the run CA's, and `contextFor` mints a host's leaf at its first CONNECT (SECURITY.md, "Who
   * holds the CA key", has the trade).
   */
  class TlsInspection private (val contextFor: String => SSLContext):

    /**
     * `consumed` replays the already-read ClientHello ahead of the socket; `host` is the CONNECT
     * host, which validateTlsIdentity proved equal to the SNI the client will verify. ALPN pinned
     * to http/1.1: an h2-only client fails the handshake rather than becoming something this
     * proxy cannot parse.
     */
    def accept(client: Socket, consumed: Array[Byte], host: String): SSLSocket =
      val socket =
        contextFor(host).getSocketFactory
          .createSocket(client, ByteArrayInputStream(consumed), false)
          .asInstanceOf[SSLSocket]

      socket.setUseClientMode(false)

      val parameters = socket.getSSLParameters
      parameters.setApplicationProtocols(Array("http/1.1"))
      socket.setSSLParameters(parameters)

      socket.startHandshake()
      socket

    /**
     * An ordinary verified TLS client connection: default trust store,
     * hostname checked, SNI set. Terminating the client's TLS is no excuse
     * to stop checking the server's.
     */
    def connect(origin: Socket, host: String): SSLSocket =
      val socket =
        SSLContext.getDefault.getSocketFactory
          .createSocket(origin, host, 443, false)
          .asInstanceOf[SSLSocket]

      val parameters = socket.getSSLParameters
      parameters.setApplicationProtocols(Array("http/1.1"))
      parameters.setEndpointIdentificationAlgorithm("HTTPS")
      parameters.setServerNames(
        java.util.List.of[SNIServerName](SNIHostName(host)),
      )
      socket.setSSLParameters(parameters)

      // A stalled handshake would pin this connection's slot; relayInspected widens the timeout once bytes flow, so a
      // slow clone is unaffected.
      socket.setSoTimeout(AgentEgressProxy.HandshakeTimeoutMillis)
      socket.startHandshake()
      socket

  object TlsInspection:
    def load(
      certificate: Path,
      privateKey: Path,
      hosts: Set[String],
    ): TlsInspection =
      val chain = readCertificateChain(certificate)
      val key = readPrivateKey(privateKey)

      // Either direction is a leaf that does not match this policy (SECURITY.md, "Who holds the CA key").
      inspectedNamesError(subjectAlternativeNames(chain.head), hosts).foreach: reason =>
        throw IllegalArgumentException(s"${AgentEgressProxy.CertificateVariable} $reason")

      val context = contextOf(chain, key)
      new TlsInspection(_ => context)

    /**
     * The run CA: a leaf per host, minted at its first CONNECT and kept least-recently-used up
     * to MintedLeaves, because a wildcard DNS name would otherwise let the sandbox mint until
     * the proxy's heap is gone, and the proxy's death is the session's egress; an evicted context
     * stays valid for any handshake holding it, and a re-mint costs milliseconds. The material is
     * checked as the launcher checks its own: a key beside a certificate it does not answer, or a
     * certificate no client would chain to, is a refused start here rather than a TLS error inside
     * the sandbox.
     */
    val MintedLeaves = 256

    def minting(certificate: Path, privateKey: Path): TlsInspection =
      val ca = readCertificateChain(certificate).head
      val key = readPrivateKey(privateKey)
      if ca.getBasicConstraints < 0 then
        throw IllegalArgumentException(
          s"${AgentEgressProxy.CaCertificateVariable} is not a CA certificate; no client would chain to what it signs",
        )
      if key.getAlgorithm != "EC" then
        throw IllegalArgumentException(
          s"${AgentEgressProxy.CaPrivateKeyVariable} is a ${key.getAlgorithm} key; the run CA's is EC",
        )
      if !keyAnswers(key, ca.getPublicKey) then
        throw IllegalArgumentException(
          s"${AgentEgressProxy.CaPrivateKeyVariable} does not answer ${AgentEgressProxy.CaCertificateVariable}",
        )
      val contexts = new java.util.LinkedHashMap[String, SSLContext](16, 0.75f, true):
        override def removeEldestEntry(eldest: java.util.Map.Entry[String, SSLContext]): Boolean =
          size > MintedLeaves
      new TlsInspection(host =>
        contexts.synchronized:
          Option(contexts.get(host)).getOrElse:
            val leaf = X509Helper.mintLeaf(host, ca, key)
            val context = contextOf(Vector(leaf.certificate), leaf.privateKey)
            contexts.put(host, context)
            context,
      )

    /** Whether `key` signs what `publicKey` verifies; false on any doubt. */
    def keyAnswers(key: PrivateKey, publicKey: PublicKey): Boolean =
      try
        val probe = Array.tabulate[Byte](32)(_.toByte)
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(key)
        signer.update(probe)
        val signature = signer.sign()
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(probe)
        verifier.verify(signature)
      catch case NonFatal(_) => false

    private def contextOf(chain: Vector[X509Certificate], key: PrivateKey): SSLContext =
      val password = Array.emptyCharArray

      val keyStore = KeyStore.getInstance("PKCS12")
      keyStore.load(null, null)
      keyStore.setKeyEntry("egress", key, password, chain.toArray)

      val keyManagers = KeyManagerFactory.getInstance(
        KeyManagerFactory.getDefaultAlgorithm,
      )
      keyManagers.init(keyStore, password)

      val context = SSLContext.getInstance("TLS")
      context.init(keyManagers.getKeyManagers, null, null)
      context

    def inspectedNamesError(covered: Set[String], required: Set[String]): Option[String] =
      if covered == required then None
      else
        val missing = (required -- covered).toVector.sorted
        val extra = (covered -- required).toVector.sorted
        val reasons =
          Option.when(missing.nonEmpty)(s"does not cover ${missing.mkString(" ")}") ++
            Option.when(extra.nonEmpty)(
              s"names ${extra.mkString(" ")}, which this proxy does not inspect",
            )
        Some(s"must name exactly the hosts this policy inspects; it ${reasons.mkString(", and ")}")

    def readCertificateChain(path: Path): Vector[X509Certificate] =
      val stream = Files.newInputStream(path)

      val certificates =
        try
          CertificateFactory
            .getInstance("X.509")
            .generateCertificates(stream)
            .asScala
            .toVector
            .collect { case certificate: X509Certificate => certificate }
        finally stream.close()

      if certificates.isEmpty then
        throw IllegalArgumentException(s"$path holds no X.509 certificate")

      certificates

    /**
     * PKCS#8 PEM, which is what the launcher's JCA `getEncoded` produces.
     * The algorithm is not named in the PEM header, so the candidates are
     * tried in turn rather than guessed from the file.
     */
    def readPrivateKey(path: Path): PrivateKey =
      val text = Files.readString(path, StandardCharsets.US_ASCII)

      val begin = "-----BEGIN PRIVATE KEY-----"
      val end = "-----END PRIVATE KEY-----"

      val start = text.indexOf(begin)
      val stop = text.indexOf(end)

      if start < 0 || stop < start then
        throw IllegalArgumentException(
          s"$path is not an unencrypted PKCS#8 private key",
        )

      val encoded =
        Base64.getMimeDecoder.decode(text.substring(start + begin.length, stop))

      val spec = PKCS8EncodedKeySpec(encoded)

      Vector("EC", "RSA", "Ed25519")
        .flatMap: algorithm =>
          try Some(KeyFactory.getInstance(algorithm).generatePrivate(spec))
          catch case NonFatal(_) => None
        .headOption
        .getOrElse(
          throw IllegalArgumentException(s"$path holds an unsupported key type"),
        )

    def subjectAlternativeNames(certificate: X509Certificate): Set[String] =
      val DnsName = 2

      Option(certificate.getSubjectAlternativeNames) match
        case None => Set.empty
        case Some(names) =>
          names.asScala.toVector
            .collect:
              case entry if entry.size == 2 && entry.get(0) == DnsName =>
                entry.get(1).toString.toLowerCase(Locale.ROOT)
            .toSet

  case class TlsClientHello(
    wireBytes: Array[Byte],
    serverName: Option[String],
    echPresent: Boolean,
  )

  object TlsClientHello:
    val HandshakeContentType = 22
    val ClientHelloHandshakeType = 1
    val ServerNameExtension = 0x0000

    /*
     * Encrypted ClientHello. Rejecting it is what makes the SNI check
     * mean anything: with ECH the visible outer SNI is a public name the CDN
     * shares, and the name that actually selects a backend is encrypted. A
     * connection whose outer SNI is an allowed host could then be served as
     * any other host on the same CDN. GREASE ECH (RFC 9849, 6.2) — the dummy
     * extension an ECH-capable client without a config sends, browsers by
     * default — is made indistinguishable from the real one, so it is refused
     * with it; doc/TODO.md has the narrowing an inspected host would admit.
     */
    val EncryptedClientHelloExtension = 0xfe0d
    val MaxTlsRecordPayloadBytes = 18 * 1024

    def read(in: InputStream, maxBytes: Int): TlsClientHello =
      require(maxBytes >= 9)

      val wire = ByteArrayOutputStream()
      val handshake = ByteArrayOutputStream()

      @tailrec
      def loop(): TlsClientHello =
        val recordHeader = readExactly(in, 5)
        val contentType = unsigned(recordHeader(0))
        val recordLength = u16(recordHeader, 3)

        if contentType != HandshakeContentType then
          throw BadTls(s"expected TLS handshake record, got content type $contentType")

        if unsigned(recordHeader(1)) != 3 then
          throw BadTls("unsupported TLS record version")

        if recordLength <= 0 || recordLength > MaxTlsRecordPayloadBytes then
          throw BadTls(s"invalid TLS record length: $recordLength")

        if wire.size() + 5 + recordLength > maxBytes then
          throw BadTls(s"TLS ClientHello exceeds $maxBytes bytes")

        val payload = readExactly(in, recordLength)
        wire.write(recordHeader)
        wire.write(payload)
        handshake.write(payload)

        val accumulated = handshake.toByteArray

        if accumulated.length < 4 then loop()
        else
          val handshakeType = unsigned(accumulated(0))
          val messageLength = u24(accumulated, 1)

          if handshakeType != ClientHelloHandshakeType then
            throw BadTls(s"expected ClientHello, got handshake type $handshakeType")

          if messageLength + 4 > maxBytes then
            throw BadTls(s"TLS ClientHello exceeds $maxBytes bytes")

          if accumulated.length < messageLength + 4 then loop()
          else if accumulated.length > messageLength + 4 then
            // never legitimate before the ServerHello — and wireBytes is forwarded verbatim on opaque tunnels, so exact
            // parsing keeps unexamined bytes from riding along
            throw BadTls("trailing bytes after ClientHello")
          else
            val payload = accumulated.slice(4, messageLength + 4)
            parsePayload(payload, wire.toByteArray)

      loop()

    def parsePayload(
      payload: Array[Byte],
      wireBytes: Array[Byte],
    ): TlsClientHello =
      val initial = Cursor(payload)

      val (_, afterLegacyVersion) = initial.u16("legacy_version")
      val afterRandom = afterLegacyVersion.skip(32, "random")

      val (sessionIdLength, afterSessionIdLength) =
        afterRandom.u8("legacy_session_id length")
      val afterSessionId =
        afterSessionIdLength.skip(sessionIdLength, "legacy_session_id")

      val (cipherSuitesLength, afterCipherSuitesLength) =
        afterSessionId.u16("cipher_suites length")

      if cipherSuitesLength < 2 || cipherSuitesLength % 2 != 0 then
        throw BadTls("invalid cipher_suites length")

      val afterCipherSuites =
        afterCipherSuitesLength.skip(cipherSuitesLength, "cipher_suites")

      val (compressionMethodsLength, afterCompressionLength) =
        afterCipherSuites.u8("compression_methods length")

      if compressionMethodsLength < 1 then
        throw BadTls("empty compression_methods")

      val afterCompression =
        afterCompressionLength.skip(
          compressionMethodsLength,
          "compression_methods",
        )

      if afterCompression.remaining == 0 then
        TlsClientHello(wireBytes, None, echPresent = false)
      else
        val (extensionsLength, afterExtensionsLength) =
          afterCompression.u16("extensions length")

        if extensionsLength != afterExtensionsLength.remaining then
          throw BadTls("extensions length does not match ClientHello")

        val (extensions, end) =
          afterExtensionsLength.takeCursor(extensionsLength, "extensions")

        if end.remaining != 0 then
          throw BadTls("trailing bytes after ClientHello extensions")

        val (serverName, echPresent) = parseExtensions(extensions)
        TlsClientHello(wireBytes, serverName, echPresent)

    @tailrec
    def parseExtensions(
      cursor: Cursor,
      serverName: Option[String] = None,
      echPresent: Boolean = false,
    ): (Option[String], Boolean) =
      if cursor.remaining == 0 then (serverName, echPresent)
      else
        val (extensionType, afterType) = cursor.u16("extension type")
        val (extensionLength, afterLength) = afterType.u16("extension length")
        val (extensionData, rest) =
          afterLength.take(extensionLength, "extension data")

        extensionType match
          case ServerNameExtension =>
            if serverName.nonEmpty then
              throw BadTls("duplicate server_name extension")

            parseExtensions(
              rest,
              parseServerName(extensionData),
              echPresent,
            )

          case EncryptedClientHelloExtension =>
            parseExtensions(rest, serverName, echPresent = true)

          case _ =>
            parseExtensions(rest, serverName, echPresent)

    def parseServerName(data: Array[Byte]): Option[String] =
      val initial = Cursor(data)
      val (listLength, names) = initial.u16("server_name list length")

      if listLength != names.remaining then
        throw BadTls("server_name list length mismatch")

      @tailrec
      def loop(
        cursor: Cursor,
        found: Option[String],
      ): Option[String] =
        if cursor.remaining == 0 then found
        else
          val (nameType, afterType) = cursor.u8("server_name type")
          val (nameLength, afterLength) = afterType.u16("server_name length")
          val (nameBytes, rest) = afterLength.take(nameLength, "server_name")

          if nameType == 0 then
            if found.nonEmpty then
              throw BadTls("duplicate host_name in server_name extension")

            if nameBytes.isEmpty then
              throw BadTls("empty TLS SNI hostname")

            if nameBytes.exists(byte => unsigned(byte) > 0x7f) then
              throw BadTls("non-ASCII TLS SNI hostname")

            val name = String(nameBytes, StandardCharsets.US_ASCII)
            loop(rest, Some(name))
          else
            loop(rest, found)

      loop(names, None)

  case class Cursor(
    bytes: Array[Byte],
    offset: Int = 0,
    limit: Int = -1,
  ):
    val actualLimit = if limit < 0 then bytes.length else limit

    require(offset >= 0 && offset <= actualLimit && actualLimit <= bytes.length)

    def remaining: Int = actualLimit - offset

    def u8(label: String): (Int, Cursor) =
      requireRemaining(1, label)
      (unsigned(bytes(offset)), copy(offset = offset + 1, limit = actualLimit))

    def u16(label: String): (Int, Cursor) =
      requireRemaining(2, label)
      (
        TLSHelper.u16(bytes, offset),
        copy(offset = offset + 2, limit = actualLimit),
      )

    def skip(count: Int, label: String): Cursor =
      requireRemaining(count, label)
      copy(offset = offset + count, limit = actualLimit)

    def take(count: Int, label: String): (Array[Byte], Cursor) =
      requireRemaining(count, label)
      (
        bytes.slice(offset, offset + count),
        copy(offset = offset + count, limit = actualLimit),
      )

    def takeCursor(count: Int, label: String): (Cursor, Cursor) =
      requireRemaining(count, label)
      (
        Cursor(bytes, offset, offset + count),
        copy(offset = offset + count, limit = actualLimit),
      )

    def requireRemaining(count: Int, label: String): Unit =
      if count < 0 || remaining < count then
        throw BadTls(s"truncated $label")

  def readExactly(in: InputStream, count: Int): Array[Byte] =
    val bytes = in.readNBytes(count)
    if bytes.length != count then
      throw EOFException(s"expected $count bytes, got ${bytes.length}")
    bytes

  def unsigned(byte: Byte): Int = byte & 0xff

  def u16(bytes: Array[Byte], offset: Int): Int =
    (unsigned(bytes(offset)) << 8) |
      unsigned(bytes(offset + 1))

  def u24(bytes: Array[Byte], offset: Int): Int =
    (unsigned(bytes(offset)) << 16) |
      (unsigned(bytes(offset + 1)) << 8) |
      unsigned(bytes(offset + 2))
