# Integration tests

## Basic guide

Running integration tests requires you to have relayer docker image present on your machine:

```BASH
docker pull ghcr.io/near/pagoda-relayer-rs-fastauth
```

Now, build mpc-recovery from the project's root:

```BASH
docker build . -t near/mpc-recovery
```

**Note**. You will need to re-build the Docker image each time you make a code change and want to run the integration tests.

Finally, run the integration tests:

```BASH
cargo test -p mpc-recovery-integration-tests
```

## FAQ

### I want to run a test, but keep the docker containers from being destroyed

You can pass environment variable `TESTCONTAINERS=keep` to keep all of the docker containers. For example:

```bash
$ TESTCONTAINERS=keep cargo test -p mpc-recovery-integration-tests
```

### There are no logs anymore, how do I debug?

The easiest way is to run one isolated test of your choosing while keeping the containers (see above):

```bash
$ TESTCONTAINERS=keep cargo test -p mpc-recovery-integration-tests test_basic_action
```

Now, you can do `docker ps` and it should list all of containers related to your test (the most recent ones are always at the top, so lookout for those). For example:

```bash
CONTAINER ID   IMAGE                                            COMMAND                  CREATED         STATUS         PORTS                                           NAMES
b2724d0c9530   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32792->19985/tcp, :::32792->19985/tcp   fervent_moore
67308ab06c5d   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32791->3000/tcp, :::32791->3000/tcp     upbeat_volhard
65ec65384af4   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32790->3000/tcp, :::32790->3000/tcp     friendly_easley
b4f90b1546ec   near/mpc-recovery:latest                         "mpc-recovery start-…"   5 minutes ago   Up 5 minutes   0.0.0.0:32789->3000/tcp, :::32789->3000/tcp     vibrant_allen
934ec13d9146   ghcr.io/near/pagoda-relayer-rs-fastauth:latest   "/usr/local/bin/entr…"   5 minutes ago   Up 5 minutes   0.0.0.0:32788->16581/tcp, :::32788->16581/tcp   sleepy_grothendieck
c505ead6eb18   redis:latest                                     "docker-entrypoint.s…"   5 minutes ago   Up 5 minutes   0.0.0.0:32787->6379/tcp, :::32787->6379/tcp     trusting_lederberg
2843226b16a9   google/cloud-sdk:latest                          "gcloud beta emulato…"   5 minutes ago   Up 5 minutes   0.0.0.0:32786->15805/tcp, :::32786->15805/tcp   hungry_pasteur
3f4c70020a4c   ghcr.io/near/sandbox:latest                      "near-sandbox --home…"   5 minutes ago   Up 5 minutes                                                   practical_elbakyan
```

Now, you can inspect each container's logs according to your needs using `docker logs <container-id>`. You might also want to reproduce some components of the test manually by making `curl` requests to the leader node (its web port is exposed on your host machine, use `docker ps` output above as the reference).

### Re-building Docker image is way too slow, is there a way I can do a faster development feedback loop?

We have a CLI tool that can instantiate a short-lived development environment that has everything except for the leader node set up. You can then seamlessly plug in your own leader node instance that you have set up manually (the tool gives you a CLI command to use as a starting point, but you can attach debugger, enable extra logs etc). Try it out now (sets up 3 signer nodes):

```bash
$ cargo run -p mpc-recovery-integration-tests -- test-leader 3
```
