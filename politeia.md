## Politeia (Pi) introduction

Politeia, or Pi, is the Decred proposal system. It is intended to allow
stakeholders to submit proposals with an accompanying statement of work and
payment schedule. This is the Decred project standard process to obtain payment
in DCR for rendered services. This process is still highly experimental and
therefore is subject to change. This document tries to establish a default
template for a software feature request. Other examples will follow for
non-code related activities (conferences, swag etc)

Note that it is typical to submit a proposal that shows "skin in the game".
That means that stakeholders expect that someone doing some work are displaying
a willingness to carry risk in the proposal. An example is that stakeholders
expect developers to write and show code before payment occurs. The existing
contractors use this model. For example, Company 0 carries the costs (and risk)
for 4-6 weeks before payout occurs. This is a feature and not a bug.  Asking
for a large sum of money without incurring costs shifts the risk to the DHG and
that incentivizes malicious behavior

## How to submit a Politeia (Pi) proposal

When authoring a request using Pi one must answer the following 4 questions:
1.  What
2.  Why
3.  How
4.  When

In the following paragraphs we are going to explore some examples. We'll use a
software feature as the example.

### What

In the *What* section we try to answer what we are proposing. This should be a
short description of the problem that will be addressed.

```
Add monitoring RPC call that can be used for status reporting and as a
heartbeat to ensure that politeiawww is functioning properly.
```

### Why

In the *Why* section we try to answer why the proposal is needed and why it is
a good idea.

```
Currently there is no prescribed way to remotely determine if politeiawww is
functioning correctly. We propose to add a single RPC that doubles as the
heartbeat and a status monitor. The idea is that monitoring software can
periodically issue the RPC and determine if an alert needs to be sent out to
the admins.
```

### How

```
1. Design and document RPC.
2. Add a priviledged RPC called Status that replies with StatusReply.
	* The Status RPC is an empty structure
	* The StatusReply structure returns a tri-state status: OK, Warning,
	  Critical. In addition to the status the RPC returns a server message
	  that can be forwarded to the administrators in case of Warning or
	  Failure.
	* The StatusReply returns interesting statistics such as: number of
	  proposals in memory, number of comments in memory etc.
3. Add refclient unit tests that validate all 3 conditions.
4. Add RPC to politeiawwwcli so that the status calls can be scripted.
```

### When

In the *When* section we try to answer what will be delivered when and when the
stakeholders get to vote on the milestones.

Create some sort of draw schedule that explains what milestones will be
delivered when. In this example we do the design and documentation first and
finish the work with the implementation of the code.

We allow for some time between the deliverables in order to leave space for a
vote by the stakeholders to see if the first step makes sense. Note that this
is a small example and therefore the timelines are a bit longish. The milestone
votes should be less than a week.

```
1. 2 hours to design and add documentation on how to use the call with some
   examples.
2. 8 hours to add the call, determine what status to set when and figure out
   what statistics to return.
3. 4 hours to add refclient validation tests.
4. 2 hours to add RPC to politeiawwwcli

In addition allow for 1 hour of overhead (going back and forth on slack/github
etc). This will bring the grand total to 17 hours at a rate of $40/h. This
proposal will therefore be capped at $680.

The proposed schedule is to do this work over 2 weeks in order to allow back
and forth on the details.

Week 1 deliverables
1. Design RPC 
2. Write documentation that includes examples

2 hours, to be completed on August 15 2018

Week 2 deliverables
1. Implement RPC
2. Implement validation tests
3. Implement politeiawwwcli

15 hours, to be completed on August 29 2018
```
