// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

/*
Package sessions implements a custom session store that uses the
gorilla/sessions and gorilla/securecookie libraries.

The only session store methods that the caller needs to use are Get() and
Save().

The caller uses Get() to initialize a new session.

The caller can save application specific key-value data to the session by
saving it to the Values field. This data is never sent to the client. It's
saved to the databse as an encoded string and can be retrieved using the
session ID.

The caller uses Save() to save the encoded session values to the database and
to save the encoded session ID to the http response cookies.

On future requests, the encoded session ID is provided by the client in the
request cookie. The caller uses Get() to decode the session ID and to lookup
the session values from the database.

The key used to encode/decode the session ID and the session values is provided
to the session store on initialization. Keys can be rotated by providing
multiple keys on initialization.
*/
package sessions
