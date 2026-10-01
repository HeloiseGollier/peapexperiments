# StateLearner Extension

[StateLearner](https://github.com/jderuiter/statelearner) is a tool that can learn state machines from implementations using a black-box approach. It makes use of LearnLib for the learning specific algorithms.

This repository is an extension of a version of [StateLearner](https://github.com/ChrisMcMStone/statelearner), which added support for handling lossy protocols (i.e. non-deterministism) + efficient learning of time based behavior (e.g. timeouts and retransmissions). Our extension of that version checks counterexamples and caches them, and retries inconsistent queries three times before deleting cache entries.

StateLearner also supports learning TLS implementations, smart cards and can be extended using its socket module. 

An overview of different security protocols where state machine learning has been applied can be found [here](http://www.cs.ru.nl/~joeri/StateMachineInference.html).

## Requirements

* graphviz

## Build

To build a JAR package, run the following command in the repository directory. 

`mvn package`

The resulting JAR will be located in the `/target/` directory. 

## Usage

`java -jar stateLearner-0.0.1-SNAPSHOT.jar <configuration file>`

An example configuration `socket.properties` has been providied for learning WiFi security handshakes. The contents of this file is explaied below. 

Other example configurations can be found in the 'examples' directory.

## Configuration

Configuration parameters specified in the required `config` file include:

| Parameter | Options | Explanation |
|-----------|---------|-------------
| type | `socket`, `smartcard`, `tls` | There is built in support for testing TLS and Smartcards. For everything else, interaction is done over a socket.|
| hostname | `ip addr` | IP address of machine running learner interface (e.g. [WiFi](https://github.com/ChrisMcMStone/wifi-learner)). If run locally, then `127.0.0.1`.|
| port | `port no` | Port number of corresponding service running on above IP address |
| alphabet | ... | Space separated list of all input commands to use when learning target state machine |
| learning_algorithm | `lstar`, `ttt` etc.. | Learning algorithm to use. |
| eqtest | `wmethod`,`wpmethod`,`randomwords` | Equality checking algorithm/Counter Example finder. These require additional parameters, as shown in example config files. |
| time_learn | `true`, `false` | Improves efficiency for learning time aspects of a protocol. |
| disable_outputs | .... | Space separated list of outputs that can be assumed reset the protocol. For example, a disconnect message. |


## Publications

StateLearner (or one of its predecessors) has been used in the following publications:
* [Extending Automated Protocol State Learning for the 802.11 4-Way Handshake](http://www.cs.bham.ac.uk/~tpc/Papers/WPAlearning.pdf), Chris McMahon Stone, Tom Chothia, Joeri de Ruiter
* [Automated Reverse Engineering using Lego](https://www.usenix.org/conference/woot14/workshop-program/presentation/chalupar), Georg Chalupar, Stefan Peherstorfer, Erik Poll and Joeri de Ruiter
* [Protocol state fuzzing of TLS implementations](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/de-ruiter), Joeri de Ruiter and Erik Poll
* [A Tale of the OpenSSL State Machine: a Large-scale Black-box Analysis](http://www.cs.ru.nl/~joeri/papers/nordsec16.pdf), Joeri de Ruiter
* Looking through the PEAPhole: Security Analysis of PEAP in Eduroam and Enterprise Wi-Fi, Héloïse Gollier and Mathy Vanhoef
