Plugin Architecture
====

All politeia functionality is encapsulated into plugins. The server provides
the ability to create generic user objects that are associated with UUIDs, but
that is the extent of the native politeia user data. All other data is created
and managed by plugins.

This architecture allows for the composability of plugins. For example, if two
different applications both want to add comment functionality to their
application, they can do so by integrating the `comments` plugin into their
application. The ability to layer functionality onto your application using
composable plugins allows for rapid development with minimal maintenance.

## Plugin Types

The plugin model allows for two type of plugins:
- Functionality plugins
- Application plugins

Examples of functionality plugins are the `comments` plugin and the
`ticketvote` plugin. These are self contained plugins that are not allowed to
access external state. The `comments` plugin is only allowed to access state
inside of the `comments` plugin. This allows these plugins to be composable. An
application that wants to add comment functionality can do so without having to
worry about external dependencies or application specific behavior that other
applications have layered on top.

Unlike functionality plugins, application plugins are allowed to access
external state. These plugins are not composable and are used to extend the
functionality plugins with application specific behavior. Examples of
application plugins include the `pi` plugin and the `cms` plugin. The `pi`
plugin doesn't allow comments on proposals once the proposal voting period has
ended. This is the `pi` plugin accessing state in both the `comments` plugin
and the `ticketvote` plugin in order to create behavior that is specific to the
pi application, i.e. the Decred proposal system.

Each application (proposal system, contractor management system) should only
have one application plugin. A single plugin to rule all other plugins, so to
speak.

## Server Architecture

The politeia server can be broken into three layers:
- API layer
- Backend layer
- Plugin layer

### API layer

The `politeiawww/api/http` package adds a generic HTTP API for plugin commands.
Additional APIs that use different communication protocols, such as a
websockets API, may be added in the future.

All other APIs listed in the `politeiawww/api/` directory have been deprecated
and will be removed at some point in the future.

The plugin payloads and error handling were designed to be agnostic of the
communication protocol being used. The same request and response payloads that
are used in the HTTP API can also be used in a websockets API or in any other
additional communication methods that may be added.

### Backend Layer

The backend layer handles payload encoding/decoding, session managment,
user managment, and acting as the intermediary between the API and the
plugins.

Plugins do not have direct access to the sessions database or to the
user database. The backend handles these connections and only provides
the plugins with data that they are allowed to access.  Plugins are able
to update session and user data during the execution of certain types of
commands, ex. plugin writes, and the backend will persist those changes
once the command has finished executing.

All operations performed during the execution of plugin write commands
are atomic.

### Plugin Layer

The plugin layer contains the plugin implementations. Each plugin will have its
own plugin API that contains the plugin commands, command payloads, and plugin
errors that can be returned.

Plugins are only provided access to the data that they own. If they wish
to retrieve data from a separate plugin, they must request the data from the
plugin using commands defined in the plugin's API.

The backend manages the creation of users and updating user data. Plugins do
not have direct access to the user database, but they are able to update user
data in one of two ways.

1. Update the user object that is provided to the plugin during execution of a
   plugin write command. The backend will only provide the plugin with user
   data that is owned by the plugin. Any updates to the data are saved to the
   database by the backend on successful completion of the plugin command.
   Plugins are able to specify whether data should be saved clear text or
   encrypted. The plugins do not actually have to encrypt or decrypt any data.
   This is all handled by the backend.

2. Plugins can create and manage a database table themselves to store plugin
   user data. This option should be reserved for data that would cause
   performance issues if saved to the global user object or if the plugin needs
   to be able to query the data using SQL.
