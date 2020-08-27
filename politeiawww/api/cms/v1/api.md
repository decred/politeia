# cmswww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server while in
`cmswww` mode.  The `politeiawww` server is the web server backend and it
interacts with a JSON REST API.  This document also describes websockets for
server side notifications.  It does not render HTML.

***Contractor Management Routes***
- [cmswww API Specification](#cmswww-api-specification)
- [v1](#v1)
    - [`Invite new user`](#invite-new-user)
    - [`Register`](#register)
    - [`New invoice`](#new-invoice)
    - [`User invoices`](#user-invoices)
    - [`Set invoice status`](#set-invoice-status)
    - [`Invoices`](#invoices)
    - [`Edit invoice`](#edit-invoice)
    - [`Generate payouts`](#generate-payouts)
    - [`Support/Oppose DCC`](#supportoppose-dcc)
    - [`New DCC comment`](#new-dcc-comment)
    - [`DCC comments`](#dcc-comments)
    - [`Set DCC Status`](#set-dcc-status)
    - [`User sub contractors`](#user-sub-contractors)
    - [`CMS Users`](#cms-users)
    - [`Vote DCC`](#vote-dcc)
    - [`Vote Details`](#vote-details)
    - [`Active votes`](#active-votes)
    - [`Start vote`](#start-vote)
    - [Error codes](#error-codes)
    - [Invoice status codes](#invoice-status-codes)
    - [Line item type codes](#line-item-type-codes)
    - [Domain type codes](#domain-type-codes)
    - [Contractor type codes](#contractor-type-codes)
    - [Payment status codes](#payment-status-codes)
    - [DCC type codes](#dcc-type-codes)
    - [DCC status codes](#dcc-status-codes)
    - [`Abridged CMS User`](#abridged-cms-user)
    - [`Proposal billing info`](#proposal-billing)

**Invoice status codes**

- [`InvoiceStatusInvalid`](#InvoiceStatusInvalid)
- [`InvoiceStatusNotFound`](#InvoiceStatusNotFound)
- [`InvoiceStatusNew`](#InvoiceStatusNew)
- [`InvoiceStatusUpdated`](#InvoiceStatusUpdated)
- [`InvoiceStatusDisputed`](#InvoiceStatusDisputed)
- [`InvoiceStatusRejected`](#InvoiceStatusRejected)
- [`InvoiceStatusApproved`](#InvoiceStatusApproved)
- [`InvoiceStatusPaid`](#InvoiceStatusPaid)

**Line item type codes**

- [`LineItemTypeLabor`](#LineItemTypeLabor)
- [`LineItemTypeExpense`](#LineItemTypeExpense)
- [`LineItemTypeMisc`](#LineItemTypeMisc)

### `Invite new user`

Create a new user on the cmswww server with a registration token and email
an invitation to them to register.

Note: This call requires admin privileges.

**Route:** `POST v1/user/invite`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email is used as the web site user identity for a user. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | String | The verification token which is required when calling [`Register`](#register). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request.|

This call can return one of the following error codes:

- [`ErrorStatusUserAlreadyExists`](#ErrorStatusUserAlreadyExists)
- [`ErrorStatusVerificationTokenUnexpired`](#ErrorStatusVerificationTokenUnexpired)

* **Example**

Request:

```json
{
  "email": "69af376cca42cd9c@example.com"
}
```

Reply:

```json
{
  "verificationtoken": "fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f"
}
```

### `Register`

Verifies email address of a user account invited via
[`Invite new user`](#invite-new-user) and supply details for new user registration.

**Route:** `POST v1/register`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email address of the user. | Yes |
| verificationtoken | string | The token that was provided by email to the user. | Yes |
| publickey | string | The user's ed25519 public key. | Yes |
| username | string | A unique username for the user. | Yes |
| password | string | A password for the user. | Yes |

**Results:** none

This call can return one of the following error codes:

- [`ErrorStatusVerificationTokenInvalid`](#ErrorStatusVerificationTokenInvalid)
- [`ErrorStatusVerificationTokenExpired`](#ErrorStatusVerificationTokenExpired)
- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusMalformedUsername`](#ErrorStatusMalformedUsername)
- [`ErrorStatusDuplicateUsername`](#ErrorStatusDuplicateUsername)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)
- [`ErrorStatusDuplicatePublicKey`](#ErrorStatusDuplicatePublicKey)

**Example:**

Request:

```json
{
  "email": "69af376cca42cd9c@example.com",
  "verificationtoken": "fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f",
  "publickey": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "username": "foobar",
  "password": "69af376cca42cd9c",
}
```

Reply:

```json
{}
```

### `New invoice`

Submit a new invoice for the given month and year.

**Route:** `POST /v1/invoices/new`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| month | int16 | A specific month, from 1 to 12. | Yes |
| year | int16 | A specific year. | Yes |
| files | [`[]File`](#file) | The invoice json file and any other attachments for line items. | Yes |
| publickey | string | The user's public key. | Yes |
| signature | string | The signature of the string representation of the file payload. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| censorshiprecord | [CensorshipRecord](#censorship-record) | A censorship record that provides the submitter with a method to extract the invoice and prove that he/she submitted it. |

This call can return one of the following error codes:

- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)
- [`ErrorStatusMalformedInvoiceFile`](#ErrorStatusMalformedInvoiceFile)
- [`ErrorStatusDuplicateInvoice`](#ErrorStatusDuplicateInvoice)

**Example**

Request:

```json
{
  "month": 12,
  "year": 2018,
  "files": [{
      "name":"invoice.json",
      "mime": "text/plain; charset=utf-8",
      "digest": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "payload": "VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }
  ]
}
```

Reply:

```json
{
  "censorshiprecord": {
    "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
    "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
  }
}
```

### `User invoices`

Returns a page of the user's invoices.

**Route:** `GET /v1/user/invoices`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results:**

| | Type | Description |
|-|-|-|
| invoices | array of [`Invoice`](#invoice)s | The page of invoices. |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "invoices": [{
    "status": 4,
    "month": 12,
    "year": 2018,
    "timestamp": 1508296860781,
    "userid": "0",
    "username": "foobar",
    "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
    "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e",
    "version": "1",
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }]
}
```

### `Set invoice status`

Sets the invoice status to either `InvoiceStatusApproved`, `InvoiceStatusRejected` or `InvoiceStatusDisputed`.

Note: This call requires admin privileges.

**Route:** `POST /v1/invoice/{token}/status`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific invoice. | Yes |
| status | number | The new [status](#invoice-status-codes) for the invoice. | Yes |
| reason | string | The reason for the new status. This is only required if the status is `InvoiceStatusRejected`. | |
| signature | string | Signature of token+string(status). | Yes |
| publickey | string | The user's public key, sent for signature verification. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|-|
| invoice | [`Invoice`](#invoice) | The updated invoice. |

This call can return one of the following error codes:

- [`ErrorStatusInvoiceNotFound`](#ErrorStatusInvoiceNotFound)

**Example**

Request:

```json
{
  "invoicestatus": 4,
  "publickey": "f5519b6fdee08be45d47d5dd794e81303688a8798012d8983ba3f15af70a747c",
  "signature": "041a12e5df95ec132be27f0c716fd8f7fc23889d05f66a26ef64326bd5d4e8c2bfed660235856da219237d185fb38c6be99125d834c57030428c6b96a2576900",
  "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527"
}
```

Reply:

```json
{
  "invoice": {
    "status": 4,
    "month": 12,
    "year": 2018,
    "timestamp": 1508296860781,
    "userid": "0",
    "username": "foobar",
    "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
    "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e",
    "version": "1",
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }
}
```

### `Invoices`

This request allows administrators or invoice owners to have full view of any 
of their past invoices.  Users of the same domain may be able to see limited
information from the invoices.  This will allow for inter-domain checks and
auditing of invoices.  All private infomation will be hidden to non-admins or
invoice owners (rates, expenses, payouts, address, locations etc).  This will be
merely used to audit hours billed.

There are a few optional parameters that are available to ease searching:
Month/Year will return all the invoices submitted for that month, Status
will return all invoices of that status. UserID will only return invoices that
are owned by that userid and start time/end time will return all invoices that
were submitted in that date range.  Note: There is a max page size for date
range requests.


**Route:** `POST /v1/invoices`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| month | int16 | An optional filter that can be set (along with year) to return invoices from a given month, from 1 to 12. | No |
| year | int16 | An optional filter that can be set (along with month) to return invoices from a given year. | No |
| status | int64 | An optional filter for the list; this should be an [invoice status](#invoice-status-codes). | No |
| starttime | int64 | An optional filter that can be set with endtime for date range of submitted invoices. | No |
| endtime | int64 | An optional filter that can be set with starttime for date range of submitted invoices. | No |
| userid | int64 | An optional filter that can be set to return invoices that only match the provided userid. | No |


**Results:**

| | Type | Description |
|-|-|-|
| invoices | array of [`Invoice`](#invoice)s | The page of invoices. |

**Example**

Request:

```json
{
  "month": 12,
  "year": 2018
}
```

Reply:

```json
{
  "invoices": [{
    "status": 4,
    "month": 12,
    "year": 2018,
    "timestamp": 1508296860781,
    "userid": "0",
    "username": "foobar",
    "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
    "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e",
    "version": "1",
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }]
}
```

### `Edit invoice`

Edits an exisiting invoice and will update the status to `InvoiceStatusUpdated`.

Note: This call requires the user to be the same as the invoice creator.

**Route:** `POST /v1/invoices/edit`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific invoice. | Yes |
| files | [`[]File`](#file) | The invoice CSV file and any other attachments for line items. The first line should be a comment with the month and year, with the format: `# 2006-01` | Yes |
| publickey | string | The user's public key. | Yes |
| signature | string | The signature of the string representation of the file payload. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| invoice | [`Invoice`](#invoice) | The updated invoice. |

This call can return one of the following error codes:

- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)
- [`ErrorStatusMalformedInvoiceFile`](#ErrorStatusMalformedInvoiceFile)
- [`ErrorStatusDuplicateInvoice`](#ErrorStatusDuplicateInvoice)

**Example**

Request:

```json
{
  "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
  "files": [{
      "name":"invoice.json",
      "mime": "text/plain; charset=utf-8",
      "digest": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "payload": "VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }
  ]
}
```

Reply:

```json
{
  "invoice": {
    "status": 4,
    "month": 12,
    "year": 2018,
    "timestamp": 1508296860781,
    "userid": "0",
    "username": "foobar",
    "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
    "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e",
    "version": "1",
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }
}
```

### `Generate payouts`

Generates a list of payout information for currently approved invoices.

Note: This call requires admin privileges.

**Route:** `POST /v1/admin/generatepayouts`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results:**

| | Type | Description |
|-|-|-|
| payouts | array of [`Payout`](#payout)s | The page of invoices. |

**Example**

Request:

```json
{}

Reply:

```json
{
  "payouts": [
    {
      "contractorname": "bill",
      "username": "bill0012",
      "month": 1,
      "year": 2019,
      "token": "123afed4609f21f4e3262420a875405440f42dcdaa98c163c6610fd9d6b7e855",
      "address": "TsfDLrRkk9ciUuwfp2b8PawwnukYD7yAjGd",
      "labortotal": 120000,
      "expensetotal": 400
    }
  ]
}
```

### `Invoice comments`

Retrieve all comments for given invoice.  Note that the comments are not
sorted.

**Route:** `GET /v1/invoices/{token}/comments`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| Comments | Comment | Unsorted array of all comments |
| AccessTime | int64 | UNIX timestamp of last access time. Omitted if no session cookie is present. |

**Comment:**

| | Type | Description |
| - | - | - |
| userid | string | Unique user identifier |
| username | string | Unique username |
| timestamp | int64 | UNIX time when comment was accepted |
| commentid | string | Unique comment identifier |
| parentid | string | Parent comment identifier |
| token | string | Censorship token |
| comment | string | Comment text |
| publickey | string | Public key from the client side, sent to politeiawww for verification |
| signature | string | Signature of Token, ParentID and Comment |
| receipt | string | Server signature of the client Signature |
| resultvotes | int64 | Vote score |
| upvotes | uint64 | Pro votes |
| downvotes | uint64 | Contra votes |

**Example**

Request:

The request params should be provided within the URL:

```
/v1/invoices/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde/comments
```

Reply:

```json
{
  "comments": [{
    "comment": "I dont like this invoice",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "admin",
    "totalvotes": 0,
    "resultvotes": 0
  },{
    "comment":"but i did some good work!",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "122",
    "username": "steve",
    "totalvotes": 0,
    "resultvotes": 0
  },{
    "comment":"you're right, approving",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "admin",
    "totalvotes": 0,
    "resultvotes": 0
  }],
  "accesstime": 1543539276
}
```

### `Invoice exchange rate`

Retrieve the calculated monthly exchange rate for a given month/year

**Route:** `POST /v1/invoices/exchangerate`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| month | int16 | A specific month, from 1 to 12. | Yes |
| year | int16 | A specific year. | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| ExchangeRate | float64 | The calculated monthly average exchange rate |

**Example**

Request:

```json
{
  "month": 12,
  "year": 2018
}
```

Reply:

```json
{
  "exchangerate": "17.50659503883639"
}
```

### `Pay invoices`

Temporary command that allows administrators to set all approved invoices to paid.
This command will be removed once the address watcher for approved invoices
is complete and properly functioning.

Note: This call requires admin privileges.

**Route:** `GET /v1/admin/payinvoices`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{}
```

Reply:

```json
{}
```

### `Invoice Payouts`

This command would provide a list of invoices that were paid out in a given
date range.

Note: This call requires admin privileges.

**Route:** `GET /v1/admin/invoicepayouts`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| starttime | int64 | Start time for the invoice range (in Unix seconds) | Yes |
| endtime | int64 | End time for the invoice range (in Unix seconds) | Yes |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "starttime": "1559460156",
  "endtime": "1560460156"
}
```

Reply:

```json
{
  "invoices": [
  {
    "status": 4,
    "month": 12,
    "year": 2018,
    "timestamp": 1508296860781,
    "userid": "0",
    "username": "foobar",
    "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
    "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e",
    "version": "1",
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    },
    "lineitems": [
      {
      "type": 1,
      "domain": "Design",
      "subdomain": "dcrweb",
      "description": "Creating mock ups of the current site.",
      "proposaltoken": "",
      "labor": 7380,
      "expenses": 0
      }
    ]
  }
  ]
}
```

### `Edit user`

Allows a user to submit updates to their cms user information.

**Route:** `POST /v1/user/edit`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| githubname | string | The Github Name tied to the user. | no |
| matrixname | string | The Matrix Name tied to the user. | no |
| contractorname | string | The contractors IRL name/identity. | no |
| contractorlocation | string | Current general locaiton of the contractor. | no |
| contractorcontact | string | Email or contact information of the contractor. | no |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "githubname": "smobs",
  "matrixname": "smobs:decred.org",
  "contractorname": "Steve Mobs",
  "contractorlocation": "Cupertino, CA",
  "contractorcontact": "smobs@apple.com",
}
```

Reply:

```json
{}
```

### `Manage CMS user`

Edits a user's details. This call requires admin privileges.

**Route:** `POST /v1/admin/managecms`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| userid | string | UserID string of the user to be edited. | yes |
| domain | int | The Domain Type that the user currently has | no |
| contractortype | int | The contractor type of the user. | no |
| supervisoruserid | []string | The userid of the user (if the user is a sub contractor. ) | no |
| proposalsowned | []string | The tokens of any proposals that are "owned/managed" by this user. | no |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "domain": 1,
  "contractortype": 1,
  "supervisoruserid": "",
  "proposalsowned":["337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527"]
}
```

Reply:

```json
{}
```

### `User details`

Returns a CMS user's information.  If admin or a user requesting their own
information everything is returned.  Otherwise, a shorter public user
information response is provided.

**Route:** `GET /v1/user/details`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results:**

| | Type | Description |
|-|-|-|
| user | instance of [`CMS User`](#cmsuser) | various user details |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "user": {
    "user":
      {
        "id": "0",
        "email": "6b87b6ebb0c80cb7@example.com",
        "username": "6b87b6ebb0c80cb7",
        "isadmin": false,
        "newuserpaywalladdress": "Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
        "newuserpaywallamount": 10000000,
        "newuserpaywalltxnotbefore": 1528821554,
        "newuserpaywalltx": "",
        "newuserpaywallpollexpiry": 1528821554,
        "newuserverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "newuserverificationexpiry": 1528821554,
        "updatekeyverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "updatekeyverificationexpiry": 1528821554,
        "numofproposals": 0,
        "resetpasswordverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "resetpasswordverificationexpiry": 1528821554,
        "identities": [{
          "pubkey": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
          "isactive": true
        }],
      },
    "comments": [],
    "domain": 1,
    "githubname": "smobs",
    "matrixname": "smobs:decred.org",
    "contractortype": 1,
    "contractorname": "Steve Mobs",
    "contractorlocation": "Cupertino, CA",
    "contractorcontact": "smobs@apple.com",
    "supervisoruserid": "",
  }
}
```

### `New DCC`

Creates a new Decred Contractor Clearance proposal.  These may either be an
issuance or a revocation.  In the case of an issuance, an existing user (sponsor)
nominates a yet-to-be-approved user to join the contractors.  The sponsor also
includes a statement to support the nomination of the user.  In the case of
a revocation, an existing user (sponsor) nominates another existing user to
have their access to the contractors' group rescinded and also includes a statement
to support that revocation.

In either case, issuance or revocation, other existing contractors will
be asked to offer their support or opposition to a DCC and based upon those
results, an administrator will approve or reject the DCC.

**Route:** `POST /v1/dcc/new`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| file | [`File`](#file) | The dcc json file. | Yes |
| publickey | string | The user's public key. | Yes |
| signature | string | The signature of the string representation of the file payload. | Yes |

**Results:**

| | Type | Description |
|-|-|-|
| censorshiprecord | [CensorshipRecord](#censorship-record) | A censorship record that provides the submitter with a method to extract the dcc and prove that he/she submitted it. |

**Example**

Request:

```json
{
  "file":
  {
      "name":"dcc.json",
      "mime": "text/plain; charset=utf-8",
      "digest": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "payload": "VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
  },
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e"
}
```

Reply:

```json
{
  "censorshiprecord": {
    "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
    "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
  }
}
```

### `DCC Details`

Retrieve DCC and its details.

**Routes:** `GET /v1/dcc/{token}`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific DCC. | Yes |

**Results:**

| | Type | Description |
|-|-|-|
| dcc | [`DCC`](#dcc) | The DCC with the provided token. |

**Example**

Request:

The request params should be provided within the URL:

```
/v1/dcc/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{
    "dcc": {
      "status": 4,
      "statuschangereason": "This has been revoked due to strong support.",
      "timestamp": 1565374601,
      "dccpayload": {
        "type": 2,
        "nomineeuserid": "6638a1c9-271f-433e-bf2c-6144ddd8bed5",
        "statement": "This is a statement to support the DCC to revoke this user.",
        "domain": 2
      },
      "file": [
        {
          "name": "dcc.json",
          "mime": "text/plain; charset=utf-8",
          "digest": "cd5176184a510776abf1c394d830427f94d2f7fe4622e27ac839ceefa7fcf277",
          "payload": "eyJ0eXBlIjoyLCJub21pbmVldXNlcmlkIjoiNjYzOGExYzktMjcxZi00MzNlLWJmMmMtNjE0NGRkZDhiZWQ1Iiwic3RhdGVtZW50Ijoic2RhZnNkZmFzZmRzZGYiLCJkb21haW4iOjJ9"
        }
      ],
      "publickey": "311fa61d27b18c0033589ef1fb49edd162d791d0702cbab623ffd4486452322a",
      "signature": "8a3c5b5cb984cfb7fd59a11d2d7d11a8d50b936358541d917ba348d30bfb1d805c26686836695a9b4b347feee6a674b689b448ed941280874a4b8dbdf360600b",
      "version": "1",
      "sponsoruserid": "b35ab9d3-a98d-4170-ad5a-85b5bce9fb10",
      "sponsorusername": "bsaget",
      "supportuserids": [],
      "againstuserids": [
        "a5c98ca0-7369-4147-8902-3d268ec2fb24"
      ],
      "censorshiprecord": {
        "token": "edd0882152f9800e7a6240f23d7310bd45145eb85ec463458de828b631083d84",
        "merkle": "cd5176184a510776abf1c394d830427f94d2f7fe4622e27ac839ceefa7fcf277",
        "signature": "4ea9f76a6c6659d4936aa556182604a3099778a981ebf500d5d47424b7ba0127ab033202b0be7872d09473088c04e9d1145f801455f0ae07be29e2f2d99ac00f"
      },
    "publickey": "311fa61d27b18c0033589ef1fb49edd162d791d0702cbab623ffd4486452322a",
    "signature": "8a3c5b5cb984cfb7fd59a11d2d7d11a8d50b936358541d917ba348d30bfb1d805c26686836695a9b4b347feee6a674b689b448ed941280874a4b8dbdf360600b",
    "version": "1",
    "statement": "",
    "domain": 0,
    "sponsoruserid": "b35ab9d3-a98d-4170-ad5a-85b5bce9fb10",
    "sponsorusername": "bsaget",
    "supportuserids": [],
    "againstuserids": [
      "a5c98ca0-7369-4147-8902-3d268ec2fb24"
    ],
    "censorshiprecord": {
      "token": "edd0882152f9800e7a6240f23d7310bd45145eb85ec463458de828b631083d84",
      "merkle": "cd5176184a510776abf1c394d830427f94d2f7fe4622e27ac839ceefa7fcf277",
      "signature": "4ea9f76a6c6659d4936aa556182604a3099778a981ebf500d5d47424b7ba0127ab033202b0be7872d09473088c04e9d1145f801455f0ae07be29e2f2d99ac00f"
    }
  }
}
```

### `Get DCCs`

Retrieve DCCs by status.

**Routes:** `POST /v1/dcc`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| status | int | Returns all of the DCCs depending by the provided status. | Yes |

**Results:**

| | Type | Description |
|-|-|-|
| dccs | [`DCC`](#dcc) | The DCCs with the provided status. |

**Example**

Request:

```json
{
  "status":1,
},

Reply:

```json
{
  "dccs": [{
    "dcc": {
      "type": 2,
      "status": 4,
      "statuschangereason": "This has been revoked due to strong support.",
      "timestamp": 1565374601,
      "dccpayload": {
        "type": 2,
        "nomineeuserid": "6638a1c9-271f-433e-bf2c-6144ddd8bed5",
        "statement": "This is a statement to support the DCC to revoke this user.",
        "domain": 2
      },
      "file": [
        {
          "name": "dcc.json",
          "mime": "text/plain; charset=utf-8",
          "digest": "cd5176184a510776abf1c394d830427f94d2f7fe4622e27ac839ceefa7fcf277",
          "payload": "eyJ0eXBlIjoyLCJub21pbmVldXNlcmlkIjoiNjYzOGExYzktMjcxZi00MzNlLWJmMmMtNjE0NGRkZDhiZWQ1Iiwic3RhdGVtZW50Ijoic2RhZnNkZmFzZmRzZGYiLCJkb21haW4iOjJ9"
        }
      ],
      "publickey": "311fa61d27b18c0033589ef1fb49edd162d791d0702cbab623ffd4486452322a",
      "signature": "8a3c5b5cb984cfb7fd59a11d2d7d11a8d50b936358541d917ba348d30bfb1d805c26686836695a9b4b347feee6a674b689b448ed941280874a4b8dbdf360600b",
      "version": "1",
      "statement": "",
      "domain": 0,
      "sponsoruserid": "b35ab9d3-a98d-4170-ad5a-85b5bce9fb10",
      "sponsorusername": "bsaget",
      "supportuserids": [],
      "againstuserids": [
        "a5c98ca0-7369-4147-8902-3d268ec2fb24"
      ],
      "censorshiprecord": {
        "token": "edd0882152f9800e7a6240f23d7310bd45145eb85ec463458de828b631083d84",
        "merkle": "cd5176184a510776abf1c394d830427f94d2f7fe4622e27ac839ceefa7fcf277",
        "signature": "4ea9f76a6c6659d4936aa556182604a3099778a981ebf500d5d47424b7ba0127ab033202b0be7872d09473088c04e9d1145f801455f0ae07be29e2f2d99ac00f"
      }
    }
  }]
}
```

### `Support Oppose DCC`

Creates a vote on a DCC Record that is used to tabulate support or opposition .

**Route:** `POST /v1/dcc/supportoppose`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| vote | string | The vote for the given DCC | Yes |
| token | string | The token of the DCC to support | Yes |
| publickey | string | The submitting user's public key | Yes |
| signature | string | Signature of the Token+Vote by the submitting user | Yes |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "vote": "aye",
  "token":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e"
}
```

Reply:

```json
{}
```

### `New DCC comment`

Submit comment on given DCC.  ParentID value "0" means "comment on
proposal"; if the value is not empty it means "reply to comment".

**Route:** `POST /v1/dcc/newcomment`

**Params:**

| Parameter | Type | Description | Required |
| - | - | - | - |
| token | string | Censorship token | Yes |
| parentid | string | Parent comment identifier | Yes |
| comment | string | Comment | Yes |
| signature | string | Signature of Token, ParentID and Comment | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| token | string | Censorship token |
| parentid | string | Parent comment identifier |
| comment | string | Comment text |
| signature | string | Signature of Token, ParentID and Comment |
| publickey | string | Public key from the client side, sent to politeiawww for verification |
| commentid | string | Unique comment identifier |
| receipt | string | Server signature of the client Signature |
| timestamp | int64 | UNIX time when comment was accepted |
| resultvotes | int64 | Vote score |
| censored | bool | Has the comment been censored |
| userid | string | Unique user identifier |
| username | string | Unique username |

On failure the call shall return `400 Bad Request` and one of the following
error codes:

- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusDCCNotFound`](#ErrorStatusDCCNotFound)
- [`ErrorStatusCannotSupportOpposeCommentOnNonActiveDCC`](#ErrorStatusCannotSupportOpposeCommentOnNonActiveDCC)
- [`ErrorStatusDuplicateComment`](#ErrorStatusDuplicateComment)

**Example**

Request:

```json
{
  "token":"abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "parentid":"0",
  "comment":"I dont like this dcc",
  "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey":"4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7"
}
```

Reply:

```json
{
  "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "parentid": "0",
  "comment": "I dont like this dcc",
  "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
  "commentid": "4",
  "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
  "timestamp": 1527277504,
  "resultvotes": 0,
  "censored": false,
  "userid": "124",
  "username": "john",
}
```

### `DCC comments`

Retrieve all comments for given DCC.  Note that the comments are not
sorted.

**Route:** `GET /v1/dcc/{token}/comments`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| Comments | Comment | Unsorted array of all comments |
| AccessTime | int64 | UNIX timestamp of last access time. Omitted if no session cookie is present. |

**Comment:**

| | Type | Description |
| - | - | - |
| userid | string | Unique user identifier |
| username | string | Unique username |
| timestamp | int64 | UNIX time when comment was accepted |
| commentid | string | Unique comment identifier |
| parentid | string | Parent comment identifier |
| token | string | Censorship token |
| comment | string | Comment text |
| publickey | string | Public key from the client side, sent to politeiawww for verification |
| signature | string | Signature of Token, ParentID and Comment |
| receipt | string | Server signature of the client Signature |
| resultvotes | int64 | Vote score |

**Example**

Request:

The request params should be provided within the URL:

```
/v1/dcc/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde/comments
```

Reply:

```json
{
  "comments": [{
    "comment": "I dont like this dcc",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "admin",
    "totalvotes": 0,
    "resultvotes": 0
  },{
    "comment":"Yah this user stinks!",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "122",
    "username": "steve",
    "totalvotes": 0,
    "resultvotes": 0
  },{
    "comment":"you're right, approving",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "admin",
    "totalvotes": 0,
    "resultvotes": 0
  }],
  "accesstime": 1543539276
}
```

### `Set DCC Status`

Updates the status of a given DCC proposal.

Note: This call requires admin privileges.

**Route:** `POST /v1/dcc/{token}/status`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| reason | string | The reason for approving the DCC. | No |
| status | int | The status to which the DCC will be updated. | Yes |
| token | string | The token of the DCC to approve. | Yes |
| publickey | string | The user's public key. | Yes |
| signature | string | The signature of the string representation of the token, status and reason payload. | Yes |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "reason":"this dcc looks well supported!",
  "status": 2,
  "token":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "signature": "gdd92f26c8g38c90d2887259e88df614654g32fde76bef1438b0efg40e360f461e995d796g16b17108gbe226793ge4g52gg013428feb3c39de504fe5g1811e0e"}
```

Reply:

```json
{}
```

### `User sub contractors`

Returns a list of the user's associated subcontractors

**Route:** `GET /v1/user/subcontractors`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results:**

| | Type | Description |
|-|-|-|-|
| users | array of [`User`](#user)s | The list of subcontractors. |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "users": [
    {
    "user":
      {
        "id": "0",
        "email": "6b87b6ebb0c80cb7@example.com",
        "username": "subcontractor1",
        "isadmin": false,
        "newuserpaywalladdress": "Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
        "newuserpaywallamount": 10000000,
        "newuserpaywalltxnotbefore": 1528821554,
        "newuserpaywalltx": "",
        "newuserpaywallpollexpiry": 1528821554,
        "newuserverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "newuserverificationexpiry": 1528821554,
        "updatekeyverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "updatekeyverificationexpiry": 1528821554,
        "numofproposals": 0,
        "resetpasswordverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "resetpasswordverificationexpiry": 1528821554,
        "identities": [{
          "pubkey": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
          "isactive": true
        }],
      },
    "domain": 1,
    "githubname": "smobs",
    "matrixname": "smobs:decred.org",
    "contractortype": 3,
    "contractorname": "Steve Mobs",
    "contractorlocation": "Cupertino, CA",
    "contractorcontact": "smobs@apple.com",
    "supervisoruserid": "4",
  },
  {
    "user":
      {
        "id": "1",
        "email": "anotherexample@example.com",
        "username": "subcontractor2",
        "isadmin": false,
        "newuserpaywalladdress": "Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
        "newuserpaywallamount": 10000000,
        "newuserpaywalltxnotbefore": 1528821554,
        "newuserpaywalltx": "",
        "newuserpaywallpollexpiry": 1528821554,
        "newuserverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "newuserverificationexpiry": 1528821554,
        "updatekeyverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "updatekeyverificationexpiry": 1528821554,
        "numofproposals": 0,
        "resetpasswordverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "resetpasswordverificationexpiry": 1528821554,
        "identities": [{
          "pubkey": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
          "isactive": true
        }],
      },
    "domain": 1,
    "githubname": "sdobs",
    "matrixname": "sdobs:decred.org",
    "contractortype": 3,
    "contractorname": "Steve Dobs",
    "contractorlocation": "Cupertino, CA",
    "contractorcontact": "sdobs@apple.com",
    "supervisoruserid": "4",
  },
  ]
}
```

### `CMS Users`

Returns a list of cms users given optional filters.

**Route:** `GET /v1/cmsusers`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| domain | int | A query int to match against user's domain. | |
| contractortype | int | A query string to match user's contractor type. | |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| users | array of [Abridged CMS User](#abridged-cms-user) | The list of cms users that match the query.

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)

**Example**

Request:

```json
{
  "domain": "1",
  "username": "1"
}
```

Reply:

```json
{
  "users": []
}
```

### `Proposal Owners`

Returns a list of cms users that are currently owning/mananging a given proposal.

**Route:** `GET /v1/proposals/owner`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| proposaltoken | string | A censorship token from a proposal on Politeia. | yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| users | array of [Abridged CMS User](#abridged-cms-user) | The list of cms users that own/manage the proposal given.

**Example**

Request:

```json
{
  "proposaltoken": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b"
}
```

Reply:

```json
{
  "users": []
}
```

### `Vote DCC`

Creates a vote on a DCC Record that is used for all contractor votes.

**Route:** `POST /v1/dcc/vote`

| Parameter | Type | Description | Required |
|-|-|-|-|
| vote | string | The vote for the given DCC | Yes |
| token | string | The token of the DCC to support | Yes |
| signature | string | Signature of Token and Vote | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
{
  "vote": "aye",
  "token":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey":"4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7"
}
```

Reply:

```json
{}
```

### `Active votes`

Retrieve all dcc active votes

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `POST /v1/dcc/activevotes`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| votes | array of VoteTuple | All current active dcc votes |

**VoteTuple:**

| | Type | Description |
| - | - | - |
| dcc | ProposalRecord | DCC record |
| startvote | Vote | Vote bits, mask etc |
| starvotereply | StartVoteReply | Vote details (user weights, start block etc |

**Example**

Request:

``` json
{}
```

Reply:

```json
{
  "votes": [{
    "dcc": {
      "name":"This is a description",
      "status":4,
      "timestamp":1523902523,
      "userid":"",
      "publickey":"d64d80c36441255e41fc1e7b6cd30259ff9a2b1276c32c7de1b7a832dff7f2c6",
      "signature":"3554f74c112c5da49c6ee1787770c21fe1ae16f7f1205f105e6df1b5bdeaa2439fff6c477445e248e21bcf081c31bbaa96bfe03acace1629494e795e5d296e04",
      "files":[],
      "censorshiprecord": {
        "token":"8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
        "merkle":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
        "signature":"97b1bf0d63d7689a2c6e66e32358d48e98d84e5389f455cc135b3401277d3a37518827da0f2bc892b535937421418e7e8ba6a4f940dfcf19a219867fa8c3e005"
      }
    }
  }],
  "vote": {
    "token":"8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
    "mask":3,
    "duration":2016,
    "Options": [{
      "id":"no",
      "description":"Don't approve dcc",
      "bits":1
    },{
      "id":"yes",
      "description":"Approve dcc",
      "bits":2
    }]
  },
  "votedetails": {
    "startblockheight":"282893",
    "startblockhash":"000000000227ff9b6bf3af53accb81e4fd1690ae44d521a665cb988bcd02ad94",
    "endheight":"284909",
    "userweights": []
  }
}
```

### `Vote details`

Vote details returns all of the relevant dcc vote information for the
given dcc token.  This includes all of the vote parameters and voting
options.

The returned version specifies the start vote version that was used to initiate
the voting period for the given dcc. See the [`Start vote`](#start-vote)
documentation for more details on the differences between the start vote
versions.

The "vote" field is a base64 encoded JSON byte slice of the Vote and will need
to be decoded according to the returned version. See the
[`Start vote`](#start-vote) documentation for more details on the differences
between the Vote versions.

**Route:** `POST /dcc/votedetails`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | The token of the DCC to retreive details | Yes |

**Results (VoteDetailsReply):**

| | Type | Description |
| - | - | - |
| version | uint32 | Start vote version |
| vote | string | JSON encoded Vote |
| publickey | string | Key used for signature |
| signature | string | Start vote signature |
| startblockheight | uint32 | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | uint32 | End block height of the vote |
| userweights | []string | All userids + weights for eligible voters |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusDCCNotFound`](#ErrorStatusDCCNotFound)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)

**Example**

Reply:

```
{
  "version": 2,
  "vote": "{}",
  "publickey": "8139793b84ad5efc48f395bbc53cc4be101936bc72167cd10c649e1e09bf698b",
  "signature": "994c893b6c26c17f900c06f01aa68cc8008af52fcaf0ab223aed810833dbafe6da08728d2a76ea48b45b3a75c48fb8ce89a3feb4a460ad6b6e741f248c4fff0c",
  "startblockheight": 342692,
  "startblockhash": "0000005e341105be45fb9a7fe24d5ca7879e07bfb1ed2f786ee5ebc220ac1959",
  "endblockheight": 344724,
  "userweights":[]
}
```
### `Start vote`

Start the voting period on the given dcc proposal that has been contentious.

Signature is a signature of the hex encoded SHA256 digest of the JSON encoded
Vote struct.

**Route:** `POST /v1/dcc/startvote`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | Public key used to sign the vote | Yes |
| vote | [`Vote`](#vote) | Vote details | Yes |
| signature | string | Signature of the Vote digest | Yes |

**Results (StartVoteReply):**

| | Type | Description |
| - | - | - |
| startblockheight | number | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | number | End block height of the vote |
| userweights | []string | All user ids + "," + weight |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusDCCNotFound`](#ErrorStatusDCCNotFound)
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidVoteOptions`](#ErrorStatusInvalidVoteOptions)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusInvalidVoteType`] (#ErrorStatusInvalidVoteType)

**Example**

Request:

``` json
{
  "publickey": "d64d80c36441255e41fc1e7b6cd30259ff9a2b1276c32c7de1b7a832dff7f2c6",
  "vote": {
    "token": "127ea26cf994dabc27e115da0eb90a5657590e2ccc4e7c23c7f80c6fe4afaa59",
    "type": 1,
    "mask": 3,
    "duration": 2016,
    "Options": [{
      "id": "no",
      "description": "Don't approve dcc",
      "bits": 1
    },{
      "id": "yes",
      "description": "Approve dcc",
      "bits": 2
    }]
  },
  "signature": "5a40d699cdfe5ee31472ec252982e60265a345cd58e4a07b183cf06447b3942d06981e1bfaf8430195109d51428458449446fbfa1d7059aebedc4df769ddb300"
}
```

Reply:

```json
{
  "startblockheight": 282899,
  "startblockhash":"00000000017236b62ff1ce136328e6fb4bcd171801a281ce0a662e63cbc4c4fa",
  "endblockheight": 284915,
  "userweights":[]
}
```

### `Proposal Billing Summary`

Retrieve all billing information for all approved proposals.

This retrieves the tokens for approved proposals and uses those tokens to
search through the database for invoices that have line-items that have that
as proposal token added.

There is also a basic pagination feature implemented with an offset and a 
page count of proposals to return.  Note, there is a max proposal
spending list page count.  If above 20, then it will be set to that max.
These are optional and if both unset, all proposal summaries will be returned.  

Note: This call requires admin privileges.

**Route:** `GET /v1/proposals/spendingsummary`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| offset | int | Page offset | No |
| count | int | Page count | No |

**Results:**

| | Type | Description |
| - | - | - |
| proposals | Array of ProposalSpending | Aggregated information of spending for all approved proposals. |

**ProposalSpending:**

| | Type | Description |
| - | - | - |
| token | string | Censorship record token of proposal. |
| title | string | Title of approved proposal. |
| totalbilled | int64 | Total billed against the proposal (in US Cents) |
| invoices | Array of InvoiceRecord | All (partially filled) invoice records that have line items with the proposal token. |

**Example**

Request:

``` json
{}
```

Reply:

```json
{
  "proposals": [{
    "token": "8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
    "title": "Super awesome proposal!",
    "totalbilled": 115000,
    "invoices": [
        {
          "status": 0,
          "timestamp": 0,
          "userid": "5c36086c-fa22-4c53-aee1-adafc4446751",
          "username": "admin",
          "publickey": "c0876a34451431b77ee9cd2e65662d0829010e0285d9fe1cc1e3ea20005b88bf",
          "signature": "",
          "file": null,
          "version": "",
          "input": {
            "version": 0,
            "month": 5,
            "year": 2020,
            "exchangerate": 1411,
            "contractorname": "",
            "contractorlocation": "",
            "contractorcontact": "",
            "contractorrate": 5000,
            "paymentaddress": "",
            "lineitems": [  {
                "type": 1,
                "domain": "Development",
                "subdomain": "dvdddasf",
                "description": "sadfasdfsdf",
                "proposaltoken": "0de5bd82bcccf22f4ccd1881fc9d88159ace56d0c1cfc7dcd86656e738e46a87",
                "subuserid": "",
                "subrate": 0,
                "labor": 1380,
                "expenses": 0
              }
            ]
          }
        }
      ]
    }]
  }
}
```

### `Proposal Billing Details`

Retrieve all billing information for the given proposal token.

Note: This call requires admin privileges.

**Route:** `POST /v1/proposals/spendingdetails`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token for approved proposal. | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| details | ProposalSpending | Aggregated information for the given proposal token. |

**ProposalSpending:**

| | Type | Description |
| - | - | - |
| token | string | Censorship record token of proposal. |
| title | string | Title of approved proposal. |
| totalbilled | int64 | Total billed against the proposal (in US Cents) |
| invoices | Array of InvoiceRecord | All (partially filled) invoice records that have line items with the proposal token. |

**Example**

Request:

``` json
{
  "token": "0de5bd82bcccf22f4ccd1881fc9d88159ace56d0c1cfc7dcd86656e738e46a87"
}
```

Reply:

```json
{
  "details": {
    "token": "8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
    "title": "Super awesome proposal!",
    "totalbilled": 115000,
    "invoices": [
        {
          "status": 0,
          "timestamp": 0,
          "userid": "5c36086c-fa22-4c53-aee1-adafc4446751",
          "username": "admin",
          "publickey": "c0876a34451431b77ee9cd2e65662d0829010e0285d9fe1cc1e3ea20005b88bf",
          "signature": "",
          "file": null,
          "version": "",
          "input": {
            "version": 0,
            "month": 5,
            "year": 2020,
            "exchangerate": 1411,
            "contractorname": "",
            "contractorlocation": "",
            "contractorcontact": "",
            "contractorrate": 5000,
            "paymentaddress": "",
            "lineitems": [  {
                "type": 1,
                "domain": "Development",
                "subdomain": "dvdddasf",
                "description": "sadfasdfsdf",
                "proposaltoken": "0de5bd82bcccf22f4ccd1881fc9d88159ace56d0c1cfc7dcd86656e738e46a87",
                "subuserid": "",
                "subrate": 0,
                "labor": 1380,
                "expenses": 0
              }
            ]
          }
        }
      ]
    }
  }
    
```

### Error codes

| Status | Value | Description |
|-|-|-|
| <a name="ErrorStatusMalformedName">ErrorStatusMalformedName</a> | 1001 | Invalid name entered for CMS registration. |
| <a name="ErrorStatusMalformedLocation">ErrorStatusMalformedLocation</a> | 1002 | Invalid location entered for CMS registration. |
| <a name="ErrorStatusInvoiceNotFound">ErrorStatusInvoiceNotFound</a> | 1003 | Request invoice not found. |
| <a name="ErrorStatusInvalidMonthYearRequest">ErrorStatusInvalidMonthYearRequest</a> | 1004 | Month and/or was improperly entered for an invoice. |
| <a name="ErrorStatusMalformedInvoiceFile">ErrorStatusMalformedInvoiceFile</a> | 1005 | The invoice file submitted was malformed and not acceptable. |
| <a name="ErrorStatusInvalidInvoiceStatusTransition">ErrorStatusInvalidInvoiceStatusTransition</a> | 1006 | Status update attempted an invalid status transition. |
| <a name="ErrorStatusReasonNotProvided">ErrorStatusReasonNotProvided</a> | 1007 | No reason provided for status updated. |
| <a name="ErrorStatusInvoiceDuplicate">ErrorStatusInvoiceDuplicate</a> | 1008 | Invoice is a duplicate. |
| <a name="ErrorStatusInvalidPaymentAddress">ErrorStatusInvalidPaymentAddress</a> | 1009 | Invalid payment address was submitted. |
| <a name="ErrorStatusMalformedLineItem">ErrorStatusMalformedLineItem</a> | 1010 | Line item in an invoice was malformed and invalid. |
| <a name="ErrorStatusInvoiceMissingName">ErrorStatusInvoiceMissingName</a> | 1011 | Submitted invoice missing contractor name. |
| <a name="ErrorStatusInvoiceMissingContact">ErrorStatusInvoiceMissingContact</a> | 1013 | Submitted invoice missing contractor contact. |
| <a name="ErrorStatusInvoiceMissingRate">ErrorStatusInvoiceMissingRate</a> | 1014 | Submitted invoice missing contractor rate. |
| <a name="ErrorStatusInvoiceInvalidRate">ErrorStatusInvoiceInvalidRate</a> | 1015 | Submitted contractor rate is invalid (either too high or low). |
| <a name="ErrorStatusInvoiceMalformedContact">ErrorStatusInvoiceMalformedContact</a> | 1016 | Malformed contractor contact was entered. |
| <a name="ErrorStatusMalformedProposalToken">ErrorStatusMalformedProposalToken</a> | 1017 | Malformed proposal token for a line item. |
| <a name="ErrorStatusMalformedDomain">ErrorStatusMalformedDomain</a> | 1018 | Malformed domain for a line item. |
| <a name="ErrorStatusMalformedSubdomain">ErrorStatusMalformedSubdomain</a> | 1019 | Malformed subdomain for a line item. |
| <a name="ErrorStatusMalformedDescription">ErrorStatusMalformedDescription</a> | 1020 | Malformed description for a line item. |
| <a name="ErrorStatusWrongInvoiceStatus">ErrorStatusWrongInvoiceStatus</a> | 1021 | Wrong status for an invoice to be editted (approved, rejected, paid). |
| <a name="ErrorStatusInvoiceRequireLineItems">ErrorStatusInvoiceRequireLineItems</a> | 1022 | Invoices require at least 1 line item to be included. |
| <a name="ErrorStatusInvalidInvoiceMonthYear">ErrorStatusInvalidInvoiceMonthYear</a> | 1024 | An invalid month/year was detected in an invoice. |
| <a name="ErrorStatusInvalidExchangeRate">ErrorStatusInvalidExchangeRate</a> | 1025 | Invalid Exchange Rate |
| <a name="ErrorStatusInvalidLineItemType">ErrorStatusInvalidLineItemType</a> | 1026 | An invalid line item type was attempted. |
| <a name="ErrorStatusInvalidLaborExpense">ErrorStatusInvalidLaborExpense</a> | 1027 | An invalid value was entered into labor or expenses. |
| <a name="ErrorStatusDuplicatePaymentAddress">ErrorStatusDuplicatePaymentAddress</a> | 1028 | An duplicate payment address was entered. |
| <a name="ErrorStatusInvalidDatesRequested">ErrorStatusInvalidDatesRequested</a> | 1029 | Invalid dates were submitted for a request. |
| <a name="ErrorStatusInvalidInvoiceEditMonthYear">ErrorStatusInvalidInvoiceEditMonthYear</a> | 1030 | Invoice month/year was attempted to be edited. |
| <a name="ErrorStatusInvalidDCCType">ErrorStatusInvalidDCCType</a> | 1031 | An invalid DCC type was detected. |
| <a name="ErrorStatusInvalidNominatingDomain">ErrorStatusInvalidNominatingDomain</a> | 1032 | An invalid nominating domain was detected.  Domain must match sponsoring user's domain. |
| <a name="ErrorStatusMalformedSponsorStatement">ErrorStatusMalformedSponsorStatement</a> | 1033 | The sponsor statement was malformed. |
| <a name="ErrorStatusMalformedDCCFile">ErrorStatusMalformedDCCFile</a> | 1034 | The DCC files was malformed. |
| <a name="ErrorStatusInvalidDCCComment">ErrorStatusInvalidDCCComment</a> | 1035 | A DCC comment was invalid. |
| <a name="ErrorStatusInvalidDCCStatusTransition">ErrorStatusInvalidDCCStatusTransition</a> | 1036 | An invalid DCC status transition. |
| <a name="ErrorStatusDuplicateEmail">ErrorStatusDuplicateEmail</a> | 1037 | A duplicate email address was detected. |
| <a name="ErrorStatusInvalidUserNewInvoice">ErrorStatusInvalidUserNewInvoice</a> | 1038 | The user was not allowed to create a new invoice. |
| <a name="ErrorStatusInvalidDCCNominee">ErrorStatusInvalidDCCNominee</a> | 1039 | The user that was nominated was invalid, either not found or not a potential nominee. |
| <a name="ErrorStatusDCCNotFound">ErrorStatusDCCNotFound</a> | 1040 | A requested DCC proposal was not able to be located based on the provided token. |
| <a name="ErrorStatusWrongDCCStatus">ErrorStatusWrongDCCStatus</a> | 1041 | A user is unable to support/oppose/comment on a DCC that is not active. |
| <a name="ErrorStatusInvalidSupportOppose">ErrorStatusInvalidSupportOppose</a> | 1042 | An invalid "vote" for a support or oppose request.  Must be "aye" or "nay". |
| <a name="ErrorStatusDuplicateSupportOppose">ErrorStatusDuplicateSupportOppose</a> | 1043 | A user attempted to support or oppose a DCC multiple times. |
| <a name="ErrorStatusUserIsAuthor">ErrorStatusUserIsAuthor</a> | 1044 | A user attempted to support or oppose a DCC that they authored. |
| <a name="ErrorStatusInvalidUserDCC">ErrorStatusInvalidUserDCC</a> | 1045 | A user with an invalid status attempted to complete a DCC task. |
| <a name="ErrorStatusInvalidDCCContractorType">ErrorStatusInvalidDCCContractorType</a> | 1046 | An invalid contractor type was attempted to be used in a DCC proposal. |
| <a name="ErrorStatusInvalidTypeSubHoursLineItem">ErrorStatusInvalidTypeSubHoursLineItem</a> | 1047 | A non-supervisor user attempted to sumbit a `subcontractor` line item |
| <a name="ErrorStatusMissingSubUserIDLineItem">ErrorStatusMissingSubUserIDLineItem</a> | 1048 | Subcontractor ID cannot be blank |
| <a name="ErrorStatusInvalidSubUserIDLineItem">ErrorStatusInvalidSubUserIDLineItem</a> | 1049 | An invalid subcontractor ID was attempted to be used. |
| <a name="ErrorStatusInvalidSupervisorUser">ErrorStatusInvalidSupervisorUser</a> | 1050 | An invalid Supervisor User ID was attempted to be used. |

### Invoice status codes

| Status | Value | Description |
|-|-|-|
| <a name="InvoiceStatusInvalid">InvoiceStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="InvoiceStatusNotFound">InvoiceStatusNotFound</a> | 1 | The invoice was not found. |
| <a name="InvoiceStatusNew">InvoiceStatusNew</a> | 2 | The invoice has not been reviewed by an admin. |
| <a name="InvoiceStatusUpdated">InvoiceStatusUpdated</a> | 3 | The invoice has been changed and the changes have not been reviewed by an admin. |
| <a name="InvoiceStatusDisputed">InvoiceStatusDisputed</a> | 4 | A portion of the invoice has been disputed and requires contractor resolution. |
| <a name="InvoiceStatusRejected">InvoiceStatusRejected</a> | 5 | The invoice has been rejected by an admin. |
| <a name="InvoiceStatusApproved">InvoiceStatusApproved</a> | 6 | The invoice has been approved by an admin. |
| <a name="InvoiceStatusPaid">InvoiceStatusPaid</a> | 7 | The invoice has been paid. |

### Line item type codes

| Type | Value | Description |
|-|-|-|
| <a name="LineItemTypeInvalid">LineItemTypeInvalid</a>| 0 | An invalid type. This shall be considered a bug. |
| <a name="LineItemTypeLabor">LineItemTypeLabor</a>| 1 | Line items that correspond to laborious activities. |
| <a name="LineItemTypeExpense">LineItemTypeExpense</a> | 2 | Line items that cover expensed costs. |
| <a name="LineItemTypeMisc">LineItemTypeMisc</a> | 3 | Any line item that doesn't fall into the above 2 categories. |

### Domain type codes
| Type | Value | Description |
|-|-|-|
| <a name="DomainTypeInvalid">DomainTypeInvalid</a>| 0 | An invalid Domain type. This shall be considered a bug. |
| <a name="DomainTypeDeveloper">DomainTypeDeveloper</a>| 1 | Development work, typically writing code or designing software architecture. |
| <a name="DomainTypeMarketing">DomainTypeMarketing</a>| 2 | Marketing work, typically event planning, publication outreach or writing. |
| <a name="DomainTypeCommunity">DomainTypeCommunity</a>| 3 | Community work, typically organizing and interacting with various online communities. |
| <a name="DomainTypeDesign">DomainTypeDesign</a>| 4 | Design work, typically creating art, web design or sound production for the project. |
| <a name="DomainTypeResearch">DomainTypeResearch</a>| 5 | Research work, typically looking deeper into various subjects closely related to the project. |
| <a name="DomainTypeDocumentation">DomainTypeDocumentation</a>| 6 | Documentation work, typically writing documents that help users understand the project (and its software) better. |

### Contractor type codes
| Type | Value | Description |
|-|-|-|
| <a name="ContractorTypeInvalid">ContractorTypeInvalid</a>| 0 | An invalid Contractor type.  This shall be considered a bug. |
| <a name="ContractorTypeDirect">ContractorTypeDirect</a>| 1 | A direct contractor that does not work under another organization. Able to submit invoices. |
| <a name="ContractorTypeSupervisor">ContractorTypeSupervisor</a>| 2 | The supervising manager of a team of sub contractors.  Able to submit invoices for themselves and subs. |
| <a name="ContractorTypeSubContractor">ContractorTypeSubContractor</a>| 3 | A sub contractor that works for a supervising manager.  NOT able to submit invoices. |
| <a name="ContractorTypeRevoked">ContractorTypeRevoked</a>| 4 | A contractor that has been revoked by a DCC. |
| <a name="ContractorTypeDormant">ContractorTypeDormant</a>| 5 | A contractor that has left for a period of time without invoice or contact. |
| <a name="ContractorTypeNominee">ContractorTypeNominee</a>| 6 | A nominated contractor that has an associated DCC. |


### Payment status codes
| Status | Value | Description |
|-|-|-|
| <a name="PaymentStatusInvalid">PaymentStatusInvalid</a>| 0 | Invalid status. |
| <a name="PaymentStatusWatching">PaymentStatusWatching</a>| 1 | Payment is currently watching. |
| <a name="PaymentStatusPaid">PaymentStatusPaid</a>| 2 | Payment has been observed to have been paid. |

### DCC type codes
| Type | Value | Description |
|-|-|-|
| <a name="DCCTypeInvalid">DCCTypeInvalid</a>| 0 | Invalid type. |
| <a name="DCCTypeIssuance">DCCTypeIssuance</a>| 1 | DCC issuance proposal. |
| <a name="DCCTypeRevocation">DCCTypeRevocation</a>| 2 | DCC revocation proposal. |

### DCC status codes
| Status | Value | Description |
|-|-|-|
| <a name="DCCStatusInvalid">DCCStatusInvalid</a>| 0 | Invalid status. |
| <a name="DCCStatusActive">DCCStatusActive</a>| 1 | Currently active issuance/revocation (awaiting sponsors). |
| <a name="DCCStatusSupported">DCCStatusSupported</a>| 2 | Fully supported issuance/revocation (received enough sponsors to proceed). |
| <a name="DCCStatusApproved">DCCStatusApproved</a>| 3 | Approved issuance/revocation |
| <a name="DCCStatusRejected">DCCStatusRejected</a>| 4 | Rejected issuance/revocation |
| <a name="DCCStatusDebate">DCCStatusDebate</a>| 5 | If a issuance/revocation receives enough comments, it would enter a "debate" status that would require a full contractor vote (to be added later).  |

### `Abridged CMS User`

This is a shortened representation of a user, used for lists.

| | Type | Description |
|-|-|-|
| id | string | The unique id of the user. |
| username | string | Unique username. |
| contractortype | string | CMS Domain of the user. |
| domain | string | CMS contractor type of the user. |

### `Proposal Billing`

**Route:** `POST /v1/proposals/billing`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| lineitems | array | Array of line items billed by a contractor |

* **Example**

Request:

```json
{
  "token": "0de5bd82bcccf22f4ccd1881fc9d88159ace56d0c1cfc7dcd86656e738e46a87"
}
```

Reply:

```json
{
  "lineitems": [
    {
      "userid": "8172cb38-32b6-4d0f-9607-6f9f1677746c",
      "username": "admin",
      "month": 5,
      "year": 2020,
      "lineitem": {
        "type": 1,
        "domain": "Development",
        "subdomain": "uuuuu",
        "description": "wwwwww",
        "proposaltoken": "0de5bd82bcccf22f4ccd1881fc9d88159ace56d0c1cfc7dcd86656e738e46a87",
        "subuserid": "",
        "subrate": 0,
        "labor": 540,
        "expenses": 0
      }
    }
  ]
}
```
