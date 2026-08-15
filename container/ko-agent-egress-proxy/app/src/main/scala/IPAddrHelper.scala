package agentsandbox.egress

import java.net.{IDN, Inet4Address, Inet6Address, InetAddress}
import java.util.Locale

/**
 * Hostnames and IP addresses: normalization, the IP-literal test, and the
 * public-destination policy that decides which resolved addresses the proxy
 * is willing to dial.
 */
object IPAddrHelper:

  def normalizeHost(value: String): String =
    if value.isEmpty then
      throw BadRequest("empty hostname")

    val withoutTrailingDot =
      if value.endsWith(".") then value.dropRight(1)
      else value

    if withoutTrailingDot.isEmpty then
      throw BadRequest("empty hostname")

    try
      IDN
        .toASCII(withoutTrailingDot, IDN.USE_STD3_ASCII_RULES)
        .toLowerCase(Locale.ROOT)
    catch
      case ex: IllegalArgumentException =>
        throw BadRequest(s"invalid hostname: ${ex.getMessage}")

  /**
   * Expects a normalized host. Dotted-quad is not the only spelling
   * InetAddress accepts (`2130706433`, `127.1`, `0177.0.0.1`); what they
   * share is an all-digits final label, which RFC 1123 forbids in a real
   * TLD — no enumeration of the resolver's numeric forms to keep in step
   * with. ASCII digits only: Char.isDigit would accept non-ASCII digits.
   *
   * The colon test below is unreachable through every current caller and kept
   * anyway: normalizeHost runs IDN.toASCII with USE_STD3_ASCII_RULES, which
   * refuses a `:` outright, so an IPv6 literal is already a BadRequest
   * ("invalid hostname", a 400) before it can become the PolicyViolation the
   * message below describes. Keeping the test costs nothing and holds if this
   * is ever called on something normalizeHost did not vet.
   */
  def isIpLiteral(host: String): Boolean =
    if host.contains(':') then true
    else
      val lastLabel = host.split("\\.", -1).last
      lastLabel.nonEmpty && lastLabel.forall(ch => ch >= '0' && ch <= '9')

  /**
   * The single DNS lookup for a connection. Its result is what the dial loop
   * uses, so there is no window in which a second lookup could return a
   * different answer than the one that was vetted here.
   *
   * Every returned address has to pass, not merely the one that ends up being
   * used: a name that answers with one public and one loopback address is a
   * name being used to smuggle a destination, not a name with a stale record.
   */
  def resolvePublic(host: String): Vector[InetAddress] =
    val addresses = InetAddress.getAllByName(host).toVector

    if addresses.isEmpty then
      throw PolicyViolation("resolved to no addresses")

    addresses.filterNot(isPublicDestination) match
      case Vector() => addresses
      case rejected =>
        throw PolicyViolation(
          s"resolved to non-public address ${rejected.head.getHostAddress}"
        )

  /**
   * Only ordinary globally-routable destinations, per the IANA
   * special-purpose registries; IPv6 must be within 2000::/3 minus the
   * listed subranges. Review when IANA updates the registries.
   */
  def isPublicDestination(address: InetAddress): Boolean =
    address match
      case ipv4: Inet4Address =>
        !Ipv4Forbidden.exists(_.contains(ipv4))

      case ipv6: Inet6Address =>
        Ipv6GlobalUnicast.contains(ipv6) &&
          !Ipv6Forbidden.exists(_.contains(ipv6))

      case _ => false

  val Ipv4Forbidden = Vector(
    Cidr("0.0.0.0", 8),
    Cidr("10.0.0.0", 8),
    Cidr("100.64.0.0", 10),
    Cidr("127.0.0.0", 8),
    Cidr("169.254.0.0", 16),
    Cidr("172.16.0.0", 12),
    Cidr("192.0.0.0", 24),
    Cidr("192.0.2.0", 24),
    Cidr("192.88.99.0", 24),
    Cidr("192.168.0.0", 16),
    Cidr("198.18.0.0", 15),
    Cidr("198.51.100.0", 24),
    Cidr("203.0.113.0", 24),
    Cidr("224.0.0.0", 4),
    Cidr("240.0.0.0", 4)
  )

  val Ipv6GlobalUnicast = Cidr("2000::", 3)

  val Ipv6Forbidden = Vector(
    Cidr("2001::", 23),
    Cidr("2001:db8::", 32),
    Cidr("2002::", 16),
    Cidr("3fff::", 20),
    Cidr("5f00::", 16)
  )

  case class Cidr private (
    network: Array[Byte],
    prefixLength: Int
  ):
    def contains(address: InetAddress): Boolean =
      val candidate = address.getAddress

      candidate.length == network.length &&
        prefixMatches(candidate, network, prefixLength)

  object Cidr:
    def apply(address: String, prefixLength: Int): Cidr =
      val bytes = InetAddress.getByName(address).getAddress
      val maxBits = bytes.length * 8

      require(
        prefixLength >= 0 && prefixLength <= maxBits,
        s"invalid /$prefixLength for $address"
      )

      new Cidr(bytes, prefixLength)

  def prefixMatches(
    candidate: Array[Byte],
    network: Array[Byte],
    prefixLength: Int
  ): Boolean =
    val fullBytes = prefixLength / 8
    val remainingBits = prefixLength % 8

    val fullBytesMatch =
      candidate.indices
        .take(fullBytes)
        .forall(i => candidate(i) == network(i))

    if !fullBytesMatch then false
    else if remainingBits == 0 then true
    else
      val mask = (0xff << (8 - remainingBits)) & 0xff
      ((candidate(fullBytes) & 0xff) & mask) ==
        ((network(fullBytes) & 0xff) & mask)
