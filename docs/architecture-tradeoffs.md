# Architecture Trade-offs

MobileSec uses separately deployable scanning and reporting services. This is
a design choice, not experimental evidence that it outperforms a monolithic
scanner.

The separation permits specialized runtimes and independent replacement of a
scanner, but introduces network calls, MongoDB coordination, container
resource overhead, and incomplete-result states. A single MobSF Docker
deployment is operationally simpler for a user who needs one static-analysis
engine rather than composable services.

Kafka adds asynchronous delivery and decoupling where report or analysis work
continues after upload. Its cost is broker deployment, topic monitoring,
consumer recovery, duplicate-delivery handling, and added failure modes. The
HTTP notification path now retries failed downstream service requests and
persists a `partial` state with unavailable services; this is a minimum
recovery signal, not a full distributed transaction or dead-letter workflow.

For an architectural comparison, measure the same APK batch with
`scripts/run-benchmark-evaluation.js --concurrency 1` and a fixed higher
concurrency setting, while recording container CPU/RAM, elapsed time,
throughput, and generated-export bytes. Until these results are reported, the
microservice layout must be described as an implementation objective rather
than a proven performance advantage.
