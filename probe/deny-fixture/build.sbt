// The gate's "fetch non-allowlisted host via proxy" row: a resolution that must reach a host the
// build proxy refuses, on a project whose failure is the measurement. The dependency exists
// nowhere, so coursier consults every resolver; example.com is RFC 6761-reserved, so the denied
// resolver can never turn into a real artifact host.
resolvers += "denied" at "https://denied.example.com/maven2"
libraryDependencies += "invalid.example" % "nowhere" % "0.0.1"
