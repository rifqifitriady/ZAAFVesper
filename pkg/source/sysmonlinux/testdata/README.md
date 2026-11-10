`live_java_child_thread_parent.xml` is one Sysmon for Linux event exactly as the live
validation captured it (workflow run 42601419858, Ubuntu 26.04 runner, sysmonforlinux
1.6.0): `/bin/sh -c id` started by a JVM. Sysmon reports the JVM *thread* 5600 as
`ParentProcessId`, with `ParentImage` `-` and a zero `ParentProcessGuid`; the JVM's
process id was 5598. `TestLiveThreadParentFixture` replays it through the feeder.
