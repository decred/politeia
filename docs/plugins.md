Plugins
====

The plugin model allows for two type of plugins:
- Functionality plugins
- Application plugins

Examples of functionality plugins are the `comments` plugin and the
`ticketvote` plugin. These are self contained plugins that are not allowed to
access external state. The `comments` plugin is only allowed to access state
inside of the `comments` plugin. This allows these plugins to be composable. An
application that wants to add comments functionality can do so without having
to worry about external dependencies or application specific behavior that
other applications have layered on top.

Application plugins, on the other hand, are allowed to access external state.
These plugins are not composable and are used to extend the functionality
plugins with application specific behavior. Examples of application plugins
include the `pi` plugin and the `cms` plugin.

For example, the `pi` plugin doesn't allow comments on proposals once the
proposal voting period has ended. This is the `pi` plugin accessing state in
both the `comments` plugin and the `ticketvote` plugin in order to create
behavior that is specific to the decred proposal system application.

Each application (proposal system, contractor management system) should only
have one application plugin. A single plugin to rule all other plugins, so to
speak.
