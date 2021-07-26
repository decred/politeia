If I'm submitting a proposal, the exact workflow goes like this:

    1. GUI submits proposal to the records/v1/new API endpoint. The record files
     contain a index.md and a proposalmetadata.json. The record metadata streams 
     contain a UserMetadata.

    2. politeiawww receives the request and validates that the request is being 
    made by a logged in user and that the user signed using their active 
    identity. There is a pi specific hook that also makes sure the user has a 
    proposal credit to spend. If the user validation passes the request is 
    fowarded to politeiad.
    https://github.com/decred/politeia/blob/master/politeiawww/records/process.go#L23

    3. politeiad validates that the record adheres to politeiad record 
    requiments (file types, sizes, and names). If the request provides a valid 
    record as defined by the politeiad API then it gets passed to the 
    NewRecordPre plugin hooks. This is where plugins can perform their own 
    plugin specific validation.

    4. NewRecordPre plugin hooks perform their own validation. This is where the
     pi plugins verifies that the contents of a record meet the requirments for 
     a proposal (has a index.md file, has a proposalmetadata.json file, etc).

    5. If all the plugin validation passes then the record is saved to disk.

    6. The request is passed to the NewRecordPost plugin hooks. This is where 
    plugins cache any data that they may need. The tstore backend uses a generic
     key-value store so we don't have the ability to run sql queries against the
      data. To get around this, plugins need to cache data that they would need 
      for queries. For example, the usermd plugin caches the user ID to token 
      mapping so that you can query records by user ID. Once the post plugin 
      hooks are done executing, politeiad sends the reply back to politeiawww.

    7. The politeiawww records API emits a records.EventTypeNew event to the 
    event manager.
    https://github.com/decred/politeia/blob/master/politeiawww/records/process.go#L89


    8. The event manager sends the event to the pi context, which has previously
     registered for it. The pi context sends out proposal notification emails.
    https://github.com/decred/politeia/blob/master/politeiawww/pi/events.go#L37-L40
    
    9. politeiawww sends the reply back to the client.

