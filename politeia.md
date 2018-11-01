## Politeia (Pi) introduction

Politeia, or Pi, is the Decred proposal system. It is intended to facilitate the submission, discussion and approval/rejection of governance proposals. 

There are two broad types of proposal:
1. Proposals that aim to establish stake-voter support for a course of action, e.g. direction of software development, adopting or changing some policy.
2. Proposals that commit to spending project fund DCR, creating a budget that some entity can draw down against as they demonstrate progress towards the proposal's aim.

There is a fee for submitting a proposal (0.1 DCR), to limit the potential for proposal spamming.

When proposals are submitted, they are checked by Politeia administrators. Proposals that are deemed spam or invalid will be censored.

When proposals are submitted, a censorship token is generated, which the proposal's owner can use, in the case that their proposal was censored, to demonstrate that it was submitted but censored.

Valid proposals will be displayed on the Politeia platform, where they can be seen by all and discussed by Politeia members.

There is a registration fee (0.1 DCR) for creating a Politeia account. Only members who have paid this fee are eligible to submit proposals and comments, and to make up/down votes on the Politeia web platform. 

Up/down votes do not affect proposal funding decisions, they are used as soft signals and to determine display order. Up/down voting is not anonymous, the up/down voting history of Politeia accounts will be public information.

When a proposal is submitted and passes screening, it will be displayed on Politeia but voting will not open immediately. The proposer has discretion to participate in discussion with Decred stakeholders and make edits to their proposal, then decide when to trigger the ticket-voting interval. When voting is triggered, edits to the proposal can no longer be made.

Ticket-voting is used to determine whether proposals are approved by Decred's stake-governors. Ticket-voting is to be performed  from a Decred wallet with live tickets, it does not happen directly through the Politeia web platform.

Politeia's aim is to serve as the decision-making force behind the Decred Decentralized Autonomous Entity (DAE). This is an ambitious aim, Politeia and its accompanying processes are in an experimental stage and thus subject to change.

Initially at least, the disbursal of funds to successful proposals will be a manual process. Proposals that request funding should specify how much funding they require, denominated in a national currency like $USD. They should also specify a set of milestones or deliverables which will trigger the release of funds.

When a proposal is approved by ticket-voters, this gives a green light to the proposing entity to begin work. When the first milestone is met, they can make a request for the release of the first tranche of funding. This will be reviewed and, where satisfactory, will be processed. It is expected that, initially at least, all proposals requesting funding are paid in arrears.

An example is that stakeholders expect developers to write and show code before payment occurs. The existing contractors use this model. For example, Company 0 carries the costs (and risk) for 4-6 weeks before payout occurs. This is a feature and not a bug.  Asking for a large sum of money without incurring costs shifts the risk to the DAE and that incentivizes malicious behavior.

## How to submit a Politeia (Pi) proposal

When authoring a request using Pi one must answer the following 5 questions:
1.  What
2.  Why
3.  How
4.  Who
5.  When

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

### Who

In the *Who* section, describe the entity that is making the proposal, will complete the work, and will draw down on the proposal's budget. 

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

## Marketing Example

###  What
```
This proposal would fund a Decred presence at Real Blockchain Conference 2018, in Dublin, Ireland, November 11-13. It would cover costs for a booth, swag, and people to staff the booth.
```
### Why
```
Real Blockchain Conference is a top cryptocurrency conference and totally not made up. Last year's conference had 5,000 attendees and they seemed cool, good solid Decred stakeholder material. With epic swag and a physical embodiment of Stakey in attendance, a presence at this conference would raise awareness of Decred.
```
### How (much)
```
I will organize Decred's presence at this event, it will take about 20 hours of my time at 40$/hour. $800
Conference registration/booth fees: $3,000
Booth decorations: $1,000
Decred swag to give away: $2,000
3 staff on the booth for 3 (10 hour) days each at $30/hr: (3 x 3 x 10 x 30) $2,700
Stakey costume: $500
Stakey costume occupant: 3 (10 hour) days at $40/hr (that suit is warm!): $1,200
Travel expenses for booth staff: Up to $2,000
Accommodation for booth staff. We will stay at the conference hotel costing $200/night, it is unlikely that all booth staff need accommodation, but the maximum would be 200 x 3 nights x 4 staff = $2,400

Maximum total budget: $15,600
```

### Who
```
This proposal is submitted by @AllYourStake (on Slack, /u/StakeGovernor2000 on reddit). You may remember me as the organizer of Decred's presence at such blockchain events as Real Blockchain Conference 2017 and Buckets of Blockchain 2018.
I don't know exactly who the 3 booth staff and 1 Stakey suit wearer will be, I will be one of the staff and @Contributor1 is also interested.
```

### When
```
Registration fees are due by September 30th, I will pay these up-front and request full reimbursement immediately.
I will front the cost of the swag and Stakey suit, and claim this along with my travel/accommodation expenses and payment for my work, after the event.
Booth staff who are already Decred contributors will bill for their hours and expenses directly, I will serve as intermediary for any staff costs not associated with established contributors.
```
