## Contractor Management System Instructions

Welcome to Decred's Contractor Management System!  This site is being designed 
to be a functional interface for contractors to submit and invoices be processed
and, in the future, have a seat at the table in some of the contractor level 
decision making, as discussed in the stakeholder approved proposal for the 
[DCC](https://proposals.decred.org/proposals/fa38a3593d9a3f6cb2478a24c25114f5097c572f6dadf24c78bb521ed10992a4).

To begin, we will be inviting contractors to the site to begin to submit 
invoices for their completed labor or expenses.  These invoices would then be 
reviewed by an administrator for approval.  If the administrator finds any
issues or comments on the invoice they will most likely put it in "Disputed"
status.  This will require the user to edit and update any areas that were
pointed out by the administrator.  If the invoice appears to be correct it will
be "Approved" for payment. 

Currently, payments will still be processed by hand until the DAE is fully
operational.

Also note that for the initial months of CMS usage invoice DCR/USD rates will be
calculated in the same fashion as they had done before.  In the near future,
once implemented, users will see a given month's DCR/USD rate upon invoice
submission.  Upon administrator invoice approval, CMS will watch the invoice's
payment address for the amount expected.  Once observed, the invoice will be
updated with the pertinent payment information (including the txid etc).

If you have any questions or concerns about the way CMS works, please reach out
to the developers by submitting issues on [github](https://github.com/thi4go/politeia)
or finding the Politeia channel that is bridged across both Matrix and our
Discord.

### How to become a user

Currently, becoming a user requires one to be invited by an administrator.  Once
the administrator issues the invitation, one should receive an email at the
address that the DHG currently has on hand.  There will be a link in the email
that will include a verification token.  Following this link will reach a
registration page that requires entry of the email, token, username and password.
Once successfully registered a user may login via the form on the right.

### How to create invoices

Once registered a user may submit invoices at
[https://cms.decred.org/invoices/new](https://cms.decred.org/invoices/new).  
This form is relatively self explantory, but here is a quick description of each
of the currently required fields:

* Contractor Name: This is whatever name you identify yourself with the DHG, typically something beyond a mere handle or nick.
* Contractor Location: This is which country you are currently located, or primarily residing.
* Contractor Contact: Contact information incase an administrator would need to reach out to discuss something, typically an email address or chat nick.
* Contractor Rate: This is the previously agreed upon rate you will be performing work.
* Payment Address: This is the DCR address where you would like to receive payment.  

* Line Items:
  * Type: Currently can be 1 (Labor), 2 (Expense), or 3 (Misc)
  * Domain: The broad category of work performed/expenses spent (for example, Development, Marketing, Community etc).
  * Subdomain: The specific project or program of which the work or expenses are related (for example, Decrediton, dcrd, NYC Event).
  * Description: A thorough description of the work or expenses.
  * Labor: The number of hours of work performed.
  * Expenses: The cost of the line item (in USD).
