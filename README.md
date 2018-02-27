WildFly URL handler for HTTP
============================

This is module for WildFly, which ensure using Elytron AuthenticationContext
for authentication, identity propagation and SSL.

It is intended to be present in WildFly by default, but it can be installed
into current version of WildFly using steps below.

Compile
-------

        mvn clean install

Add module into WildFly
-----------------------

        bin/jboss-cli.sh
        module add --name=org.wildfly.url.http.wildfly-url-http --resources=wildfly-url-http-0.0.1-SNAPSHOT.jar --dependencies=javax.api,org.wildfly.security.elytron,org.apache.httpcomponents

Add dependency on this module to the server/standalone modules
--------------------------------------------------------------

Add following dependency:

        <module name="org.wildfly.url.http.wildfly-url-http" services="import"/>

into `module.xml` of following modules:

* org.jboss.as.server
* org.jboss.as.standalone

