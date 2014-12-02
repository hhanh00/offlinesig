import com.typesafe.sbt.SbtNativePackager._
import NativePackagerKeys._

name := "offlinesig"

scalaVersion := "2.11.4"

resolvers += "nexus" at "http://localhost:8081/nexus/content/groups/public" 

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.51",
  "joda-time" % "joda-time" % "2.4",
  "org.joda" % "joda-convert" % "1.2",
  "org.apache.commons" % "commons-lang3" % "3.3.2",
  "org.json4s" %% "json4s-native" % "3.2.10",
  "com.google.guava" % "guava" % "12.0"
)

packageArchetype.java_application
