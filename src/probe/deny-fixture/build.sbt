// The acceptance test's row "fetch unlisted host via proxy" runs in this project and measures its failure:
// - the resolution must reach a host that the build proxy refuses;
// - the dependency exists nowhere, so coursier consults every resolver;
// - RFC 6761 reserves example.com, so the denied resolver can never become a real artifact host.
resolvers += "denied" at "https://denied.example.com/maven2"
libraryDependencies += "invalid.example" % "nowhere" % "0.0.1"
