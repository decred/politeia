# cmswww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server while in 
`cmswww` mode.  The `politeiawww` server is the web server backend and it 
interacts with a JSON REST API.  This document also describes websockets for
server side notifications.  It does not render HTML.

***Contractor Management Routes***
- [`Register`](#register)
- [`Invite new user`](#invite-new-user)
- [`New invoice`](#new-invoice)
- [`User invoices`](#user-invoices)
- [`Admin invoices`](#admin-invoices)
- [`Edit invoice`](#edit-invoice)
- [`Set invoice status`](#set-invoice-status)

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

**Route:** `POST v1/user/new`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email address of the user. | Yes |
| verificationtoken | string | The token that was provided by email to the user. | Yes |
| publickey | string | The user's ed25519 public key. | Yes |
| username | string | A unique username for the user. | Yes |
| password | string | A password for the user. | Yes |
| name | string | The user's full name. | Yes |
| location | string | The user's physical location. | Yes |
| xpublickey | string | The extended public key for the user's payment account. | Yes |

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
  "name": "John Smith",
  "location": "Atlanta, GA, USA",
  "xpublickey": "9e4b1018913610c12496ec3e482f2fb42129197001c5d35d4f5848b77d2b5e5071f79b18bcab4f371c5b378280bb478c153b696003ac3a627c3d8a088cd5f00d"
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
      "name":"invoice.csv",
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

### `Admin invoices`

Retrieve a page of invoices given the month and year and status.

Note: This call requires admin privileges.

**Route:** `POST /v1/admin/invoices`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| month | int16 | An optional filter that can be set (along with year) to return invoices from a given month, from 1 to 12. | |
| year | int16 | An optional filter that can be set (along with month) to return invoices from a given year. | |
| status | int64 | An optional filter for the list; this should be an [invoice status](#invoice-status-codes). | |

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